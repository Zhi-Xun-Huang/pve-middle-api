import os
from celery import Celery
from sqlalchemy.orm import Session
from .config import get_settings
from .database import SessionLocal
from .models import UserVM, SystemConfig, IPPool
from .proxmox import ProxmoxService
from .schemas import VMCreateRequest

settings = get_settings()

# Initialize Celery
celery_app = Celery(
    "pve_tasks",
    broker=settings.redis_url,
    backend=settings.redis_url
)

# Optional: Configuration for Celery
celery_app.conf.update(
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    task_track_started=True,
)

def get_svc():
    return ProxmoxService(settings)

@celery_app.task(name="tasks.create_vm_task", bind=True)
def create_vm_task(self, payload_dict: dict):
    """
    Task to create a VM.
    """
    payload = VMCreateRequest(**payload_dict)
    svc = get_svc()
    db = SessionLocal()
    
    # We do NOT autoretry creation because it's not idempotent (creates new VMID each time).
    # Instead, we focus on compensation (rollback) if DB save fails.

    try:
        # Fetch IP Pools from DB
        ip_pools = []
        try:
            pools = db.query(IPPool).all()
            for p in pools:
                ip_pools.append({
                    "start_ip": p.start_ip,
                    "end_ip": p.end_ip,
                    "gateway": p.gateway,
                    "cidr": p.cidr,
                    "type": p.type
                })
        except Exception as e:
            print(f"Warning: Failed to fetch IP pools: {e}")

        # 1. Execute Proxmox creation
        result = svc.create_vm(payload, ip_pools)
        vmid = int(result["vmid"])
        ip = result["ip"]
        profile_info = result.get("profile", {})
        gpu_count = profile_info.get("gpus", 0)
        ib_count = gpu_count if payload.required_ib else 0

        # 2. Update Database
        try:
            vm_record = db.query(UserVM).filter(UserVM.vmid == vmid).first()
            if not vm_record:
                # Fallback if for some reason API didn't create it (shouldn't happen with new logic)
                vm_record = UserVM(
                    vmid=vmid,
                    vm_name=payload.vm_name,
                    vm_username=payload.username,
                    username=payload.creator_username,
                    user_role=payload.creator_role,
                    status="created",
                    ip_address=ip,
                    cpu_cores=profile_info.get("cores"),
                    memory_mb=profile_info.get("memory_mb"),
                    storage_gb=payload.storage_size,
                    gpu_count=gpu_count,
                    ib_count=ib_count,
                )
                db.add(vm_record)
            else:
                # Update existing record created by API
                vm_record.status = "created"
                vm_record.ip_address = ip
                vm_record.vm_username = payload.username
                # Ensure specs are accurate
                vm_record.cpu_cores = profile_info.get("cores")
                vm_record.memory_mb = profile_info.get("memory_mb")
                
            db.commit()
            
            return {"status": "success", "vmid": vmid, "ip": ip}

        except Exception as db_exc:
            # COMPENSATION TRANSACTION: Rollback Proxmox creation
            print(f"DB failed for VM {vmid}, rolling back Proxmox creation...")
            try:
                svc.delete_vm(vmid)
                print(f"Rollback successful: VM {vmid} deleted.")
            except Exception as del_exc:
                print(f"CRITICAL: Rollback failed for VM {vmid}: {del_exc}")
            raise db_exc

    except Exception as exc:
        print(f"Task create_vm failed: {exc}")
        # Mark as failed in DB and release quota
        try:
            vm_record = db.query(UserVM).filter(UserVM.vmid == payload.vmid).first()
            if vm_record:
                vm_record.status = "failed"
                vm_record.gpu_count = 0 # Release GPU quota
                vm_record.ib_count = 0
                db.commit()
        except Exception as cleanup_exc:
            print(f"Failed to cleanup failed VM record: {cleanup_exc}")
            
        raise exc
    finally:
        db.close()

@celery_app.task(name="tasks.start_vm_task", bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def start_vm_task(self, vmid: int, require_ib: bool):
    svc = get_svc()
    db = SessionLocal()
    try:
        # Fetch latest specs from DB source of truth
        vm_record = db.query(UserVM).filter(UserVM.vmid == vmid).first()
        if not vm_record:
            raise RuntimeError(f"VM {vmid} not found in DB")

        cpu_cores = vm_record.cpu_cores
        memory_mb = vm_record.memory_mb
        gpu_count = vm_record.gpu_count
        ip_address = vm_record.ip_address
        
        # Override require_ib from DB if record exists, though usually passed correctly from API
        if vm_record.ib_count > 0:
            require_ib = True
            
        # 1. Start VM via Proxmox
        result = svc.start_vm(
            vmid, 
            require_ib=require_ib, 
            cpu_cores=cpu_cores, 
            memory_mb=memory_mb,
            gpu_count=gpu_count
        )

        # 2. Wait for Network (Strict SSH Port 22 Check)
        if ip_address and ip_address != "pending":
            import time
            print(f"Waiting for SSH (port 22) to be ready on {ip_address} for VM {vmid}...")
            # Poll for up to 120 seconds (2 mins)
            for i in range(120):
                if svc.is_port_open(ip_address, 22):
                    print(f"SSH is ready for VM {vmid} (attempt {i+1})")
                    break
                time.sleep(1)
            else:
                print(f"Warning: SSH check timed out for VM {vmid} after 120s. Setting running anyway.")

        # 3. Update Status to Running
        # Re-fetch record to avoid stale state issues
        vm_record = db.query(UserVM).filter(UserVM.vmid == vmid).first()
        if vm_record:
            vm_record.status = "running"
            db.commit()

        return result

    except Exception as exc:
        # If we reached max retries, update DB status to stopped so UI doesn't spin forever
        if self.request.retries >= self.max_retries:
            print(f"Task start_vm failed after {self.max_retries} retries: {exc}")
            # Re-open session as the previous one might be in rollback state or closed
            # Actually we just used db for read, but let's be safe for the write
            try:
                vm_record = db.query(UserVM).filter(UserVM.vmid == vmid).first()
                if vm_record:
                    vm_record.status = "stopped"
                    db.commit()
            except Exception as db_exc:
                print(f"Failed to update status to stopped: {db_exc}")
        raise exc
    finally:
        db.close()

@celery_app.task(name="tasks.stop_vm_task", bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def stop_vm_task(self, vmid: int, force: bool = False):
    svc = get_svc()
    return svc.stop_vm(vmid, force=force)

@celery_app.task(name="tasks.delete_vm_task", bind=True, autoretry_for=(Exception,), retry_backoff=True, max_retries=3)
def delete_vm_task(self, vmid: int):
    svc = get_svc()
    db = SessionLocal()
    try:
        try:
            result = svc.delete_vm(vmid)
        except RuntimeError as e:
            # If VM is already gone, treat as success so we can clean up DB
            if "not found on any node" in str(e):
                result = {"status": "already_deleted"}
            else:
                raise e
        
        db_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
        if db_vm:
            # SOFT DELETE: Keep record but mark as deleted.
            # We RETAIN gpu_count/ib_count for billing history calculations.
            # However, we MUST release the IP address so it can be reused.
            db_vm.status = "deleted"
            db_vm.ip_address = None
            db.commit()
        return result
    finally:
        db.close()
