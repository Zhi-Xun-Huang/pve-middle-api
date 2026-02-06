from typing import List, Optional, Dict

import secrets
import requests
from fastapi import Depends, FastAPI, HTTPException, Query, Request, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from fastapi.openapi.docs import get_swagger_ui_html, get_redoc_html
from fastapi.openapi.utils import get_openapi
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from sqlalchemy import func, text
from sqlalchemy.exc import IntegrityError
from prometheus_fastapi_instrumentator import Instrumentator

from .config import Settings, get_settings
from .database import engine, get_db, get_auth_db
from .models import Base, UserVM, UserQuota, SystemConfig, IPPool
from .proxmox import ProxmoxService
from .schemas import (
    VMActionResponse, VMCreateRequest, VMCreateResponse, VMStatusResponse, 
    VMSummary, QuotaUpdateRequest, QuotaUpdateResponse, UserUsage, 
    SystemConfigItem, SystemConfigUpdate, IPPoolCreate, IPPoolUpdate, IPPoolResponse,
    VMMetricsResponse, FirewallRule, FirewallResponse, FirewallReorderRequest,
    AssignResellerRequest, PromoteResellerRequest
)
from .tasks import create_vm_task, start_vm_task, stop_vm_task, delete_vm_task


# Initialize Database Tables
Base.metadata.create_all(bind=engine)

# AUTO MIGRATION LOGIC
def run_migrations():
    try:
        with engine.connect() as conn:
            # Check if columns exist, if not add them
            try:
                conn.execute(text("ALTER TABLE user_quotas ADD COLUMN is_reseller BOOLEAN DEFAULT 0"))
                print("MIGRATION: Added is_reseller column")
            except Exception:
                pass # Column likely exists

            try:
                conn.execute(text("ALTER TABLE user_quotas ADD COLUMN managed_by VARCHAR(255)"))
                print("MIGRATION: Added managed_by column")
            except Exception:
                pass # Column likely exists
    except Exception as e:
        print(f"MIGRATION ERROR: {e}")

run_migrations()

security = HTTPBasic()

def get_service(settings: Settings = Depends(get_settings)) -> ProxmoxService:
    return ProxmoxService(settings)


async def verify_docs_auth(
    credentials: HTTPBasicCredentials = Depends(security),
    settings: Settings = Depends(get_settings)
):
    """
    Protects API documentation with Basic Auth.
    """
    correct_username = secrets.compare_digest(credentials.username, settings.docs_username)
    correct_password = secrets.compare_digest(credentials.password, settings.docs_password)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


async def verify_user(request: Request) -> Dict[str, str]:
# ... (verify_user 邏輯不變) ...
    """
    Verifies user identity by forwarding the request's cookies/headers to the Billing System.
    Returns user info dict if valid, raises 401 otherwise.
    """
    settings = get_settings()
    # URL of the upstream auth endpoint
    auth_url = settings.auth_api_url
    
    try:
        # Forward cookies and authorization header
        headers = {}
        if "Authorization" in request.headers:
            headers["Authorization"] = request.headers["Authorization"]
        
        # We use a timeout to prevent hanging if billing is down
        response = requests.get(
            auth_url, 
            cookies=request.cookies, 
            headers=headers, 
            timeout=5
        )
        
        if response.status_code == 200:
            data = response.json()
            # Normalize response - adapt based on actual billing API response structure
            return {
                "username": data.get("username"),
                "role": data.get("role", "user")
            }
        else:
            raise HTTPException(status_code=401, detail="Authentication failed with billing system")
            
    except requests.RequestException as e:
        print(f"Auth check failed: {e}")
        raise HTTPException(status_code=401, detail="Could not verify identity with billing system")


app = FastAPI(
    title="PVE Middle API", 
    version="0.1.1",
    docs_url=None,   # Disable automatic docs
    redoc_url=None,  # Disable automatic redoc
    openapi_url=None # Disable automatic openapi.json
)

@app.get("/openapi.json", include_in_schema=False)
async def get_open_api_endpoint(username: str = Depends(verify_docs_auth)):
    return get_openapi(title=app.title, version=app.version, routes=app.routes)

@app.get("/docs", include_in_schema=False)
async def protected_swagger_ui_html(username: str = Depends(verify_docs_auth)):
    return get_swagger_ui_html(
        openapi_url="/openapi.json",
        title=app.title + " - Swagger UI",
        oauth2_redirect_url=app.swagger_ui_oauth2_redirect_url,
        swagger_js_url="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js",
        swagger_css_url="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css",
    )

@app.get("/redoc", include_in_schema=False)
async def protected_redoc_html(username: str = Depends(verify_docs_auth)):
    return get_redoc_html(
        openapi_url="/openapi.json",
        title=app.title + " - ReDoc",
        redoc_js_url="https://unpkg.com/redoc@next/bundles/redoc.standalone.js",
    )

# Setup Prometheus Instrumentation
Instrumentator().instrument(app).expose(app)

# Enable CORS
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",  # Allows all origins (safely reflects Origin header)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods
    allow_headers=["*"],  # Allows all headers
)


@app.get("/health", tags=["Monitoring"])
async def health_check():
    """
    Simple health check endpoint for liveness probes.
    """
    return {"status": "ok", "service": "pve-middle-api"}


@app.options("/{path:path}")
async def options_handler(path: str):
    """
    Catch-all handler for OPTIONS requests to ensure CORS preflight works
    even if CORSMiddleware is bypassed (e.g. if Origin header is missing via proxy).
    """
    return {}

@app.get("/admin/system-config", response_model=List[SystemConfigItem])
async def get_system_config(
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> List[SystemConfigItem]:
    if user["role"] not in ["admin", "platform_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    configs = db.query(SystemConfig).all()
    return [SystemConfigItem(key=c.key, value=c.value, description=c.description) for c in configs]


@app.post("/admin/system-config", response_model=Dict[str, str])
async def update_system_config(
    payload: SystemConfigUpdate,
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> Dict[str, str]:
    if user["role"] not in ["admin", "platform_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    try:
        for item in payload.configs:
            config = db.query(SystemConfig).filter(SystemConfig.key == item.key).first()
            if config:
                config.value = item.value
            else:
                db.add(SystemConfig(key=item.key, value=item.value, description=item.description))
        db.commit()
        return {"status": "success", "message": "Configuration updated"}
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/admin/ip-pools", response_model=List[IPPoolResponse])
async def list_ip_pools(
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> List[IPPoolResponse]:
    if user["role"] not in ["admin", "platform_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    return db.query(IPPool).all()


@app.post("/admin/ip-pools", response_model=IPPoolResponse)
async def create_ip_pool(
    payload: IPPoolCreate,
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> IPPoolResponse:
    if user["role"] not in ["admin", "platform_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    new_pool = IPPool(**payload.dict())
    db.add(new_pool)
    try:
        db.commit()
        db.refresh(new_pool)
        return new_pool
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.put("/admin/ip-pools/{pool_id}", response_model=IPPoolResponse)
async def update_ip_pool(
    pool_id: int,
    payload: IPPoolUpdate,
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> IPPoolResponse:
    if user["role"] not in ["admin", "platform_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    pool = db.query(IPPool).filter(IPPool.id == pool_id).first()
    if not pool:
        raise HTTPException(status_code=404, detail="Pool not found")
        
    for key, value in payload.dict(exclude_unset=True).items():
        setattr(pool, key, value)
        
    try:
        db.commit()
        db.refresh(pool)
        return pool
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=str(e))


@app.delete("/admin/ip-pools/{pool_id}", response_model=Dict[str, str])
async def delete_ip_pool(
    pool_id: int,
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> Dict[str, str]:
    if user["role"] not in ["admin", "platform_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    pool = db.query(IPPool).filter(IPPool.id == pool_id).first()
    if not pool:
        raise HTTPException(status_code=404, detail="Pool not found")
        
    db.delete(pool)
    db.commit()
    return {"status": "success", "message": "Pool deleted"}


@app.get("/tasks/{task_id}")
async def get_task_status(task_id: str, user: Dict[str, str] = Depends(verify_user)):
    """
    Endpoint to check the status of a Celery task.
    """
    from celery.result import AsyncResult
    from .tasks import celery_app
    
    res = AsyncResult(task_id, app=celery_app)
    return {
        "task_id": task_id,
        "status": res.status,
        "result": res.result if res.ready() else None
    }


@app.post("/admin/promote_reseller", response_model=Dict[str, str])
async def promote_reseller(
    payload: PromoteResellerRequest,
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> Dict[str, str]:
    if user["role"] not in ["admin", "platform_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    target_user = db.query(UserQuota).filter(UserQuota.username == payload.username).first()
    if not target_user:
        target_user = UserQuota(username=payload.username, gpu_limit=0)
        db.add(target_user)
    
    target_user.is_reseller = payload.is_reseller
    db.commit()
    return {"status": "success", "message": f"User {payload.username} reseller status set to {payload.is_reseller}"}


@app.post("/admin/assign_reseller", response_model=Dict[str, str])
async def assign_reseller(
    payload: AssignResellerRequest,
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> Dict[str, str]:
    if user["role"] not in ["admin", "platform_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    # Check target
    target_user_quota = db.query(UserQuota).filter(UserQuota.username == payload.username).first()
    if not target_user_quota:
        target_user_quota = UserQuota(username=payload.username, gpu_limit=0)
        db.add(target_user_quota)
    
    if payload.reseller_username:
        # Verify reseller
        reseller = db.query(UserQuota).filter(
            UserQuota.username == payload.reseller_username, 
            UserQuota.is_reseller == True
        ).first()
        if not reseller:
            raise HTTPException(status_code=404, detail="Reseller not found or invalid")
    
    target_user_quota.managed_by = payload.reseller_username
    db.commit()
    
    msg = f"User {payload.username} assigned to {payload.reseller_username}" if payload.reseller_username else f"User {payload.username} removed from reseller"
    return {"status": "success", "message": msg}


@app.post("/vm_user_quota", response_model=QuotaUpdateResponse)
async def update_user_quota(
    payload: QuotaUpdateRequest,
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> QuotaUpdateResponse:
    if user["role"] not in ["platform_admin", "admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    user_quota = db.query(UserQuota).filter(UserQuota.username == payload.username).first()
    if not user_quota:
        user_quota = UserQuota(username=payload.username, gpu_limit=payload.gpu_limit)
        db.add(user_quota)
    else:
        user_quota.gpu_limit = payload.gpu_limit
        
    db.commit()
    db.refresh(user_quota)
    
    return QuotaUpdateResponse(
        message="Quota updated successfully",
        username=user_quota.username,
        gpu_limit=user_quota.gpu_limit
    )


@app.get("/users", response_model=List[UserUsage])
async def list_users_usage(
    db: Session = Depends(get_db),
    auth_db: Session = Depends(get_auth_db),
    user: Dict[str, str] = Depends(verify_user),
) -> List[UserUsage]:
    if user["role"] not in ["admin", "platform_admin"]:
        raise HTTPException(status_code=403, detail="Not authorized")

    # Get Users
    try:
        auth_users = auth_db.execute(text("SELECT username, role, reseller_code FROM users")).fetchall()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to query auth database: {e}")

    # Get Quotas
    quotas = db.query(UserQuota).all()
    quota_map = {q.username: q for q in quotas}

    # Get Usage
    usage_stats = db.query(
        UserVM.username,
        func.sum(UserVM.gpu_count).label("total_gpu"),
        func.count(UserVM.id).label("vm_count")
    ).filter(UserVM.status != "deleted").group_by(UserVM.username).all()
    
    usage_map = {
        u.username: {"gpu": u.total_gpu or 0, "count": u.vm_count} 
        for u in usage_stats
    }

    result = []
    for u in auth_users:
        username = u.username
        role = u.role
        res_code = u.reseller_code
        
        q_info = quota_map.get(username)
        gpu_limit = q_info.gpu_limit if q_info else 0
        
        u_stats = usage_map.get(username, {"gpu": 0, "count": 0})
        
        result.append(UserUsage(
            username=username,
            role=role,
            gpu_limit=gpu_limit,
            gpu_used=int(u_stats["gpu"]),
            vm_count=int(u_stats["count"]),
            reseller_code=res_code
        ))
        
    return result


@app.post("/vms", response_model=VMActionResponse)
async def create_vm(
    payload: VMCreateRequest,
    db: Session = Depends(get_db),
    svc: ProxmoxService = Depends(get_service),
    user: Dict[str, str] = Depends(verify_user), # Enforce auth
) -> VMActionResponse:
    try:
        # Override payload creator info with verified user info
        payload.creator_username = user["username"]
        payload.creator_role = user["role"]
        # Force the VM's login user to be the same as the creator
        payload.username = user["username"]
        
        # --- GPU Quota Check ---
        # 1. Determine requested GPUs
        profile_info = svc.get_vm_profile(payload.vm_profile)
        requested_gpus = profile_info.get("gpus", 0)
        
        # 2. Check User Quota
        user_quota = db.query(UserQuota).filter(UserQuota.username == user["username"]).first()
        if not user_quota:
            print(f"DEBUG: No quota found for {user['username']}, creating default 0...")
            # Auto-create default quota if not exists
            user_quota = UserQuota(username=user["username"], gpu_limit=0)
            db.add(user_quota)
            db.commit()
            db.refresh(user_quota)
            
        if requested_gpus > 0:
            # 3. Calculate current usage
            current_usage = db.query(func.sum(UserVM.gpu_count)).filter(
                UserVM.username == user["username"],
                UserVM.status != "deleted"
            ).scalar() or 0
            
            if (current_usage + requested_gpus) > user_quota.gpu_limit:
                raise HTTPException(
                    status_code=403,
                    detail=f"GPU quota exceeded. Limit: {user_quota.gpu_limit}, Current: {current_usage}, Requested: {requested_gpus}"
                )
        # -----------------------

        # --- IP Availability Check (Sync Pre-check) ---
        # Fetch IP pools from DB
        ip_pools_list = []
        try:
            pools = db.query(IPPool).all()
            for p in pools:
                ip_pools_list.append({
                    "start_ip": p.start_ip,
                    "end_ip": p.end_ip,
                    "gateway": p.gateway,
                    "type": p.type
                })
        except Exception as e:
            print(f"Warning: Failed to fetch IP pools: {e}")

        # Check if we have free IPs before creating DB record
        # Note: This is a "best effort" check. Race conditions can still happen in the worker.
        if not svc.check_ip_availability(payload.use_public_ip, ip_pools_list):
             raise HTTPException(
                 status_code=400,
                 detail=f"Insufficient IP resources. Please contact admin."
             )
        # -----------------------------

        # --- Pre-allocate DB Record (Prevent Race Condition) ---
        # Retry loop for VMID collision
        max_retries = 10
        allocated_vmid = None
        
        # Get initial base ID
        base_id = payload.vmid
        if not base_id:
            try:
                # Get max ID from DB to avoid collision with soft-deleted or creating VMs
                db_max_id = db.query(func.max(UserVM.vmid)).scalar() or 0
                pve_next_id = svc.get_next_id()
                
                # Start from the greater of (DB Max + 1) or PVE Next ID
                base_id = max(db_max_id + 1, pve_next_id)
            except Exception as e:
                print(f"Warning: Failed to calculate next ID: {e}")
                base_id = 100 # Fallback
        
        for attempt in range(max_retries):
            try:
                # If user provided ID, use it (only try once)
                if payload.vmid:
                    if attempt > 0: 
                        break
                    current_vmid = payload.vmid
                else:
                    # Increment locally to skip "ghost" IDs in DB that PVE considers free
                    current_vmid = base_id + attempt
                
                # 2. Create UserVM record (status=creating)
                ib_count = requested_gpus if payload.required_ib else 0
                
                new_vm = UserVM(
                    vmid=current_vmid,
                    vm_name=payload.vm_name,
                    vm_username=payload.username,
                    username=user["username"],
                    user_role=user["role"],
                    status="creating",
                    cpu_cores=profile_info.get("cores"),
                    memory_mb=profile_info.get("memory_mb"),
                    storage_gb=payload.storage_size,
                    gpu_count=requested_gpus,
                    ib_count=ib_count,
                    use_public_ip=1 if payload.use_public_ip else 0,
                )
                db.add(new_vm)
                db.commit()
                
                allocated_vmid = current_vmid
                break # Success
            except IntegrityError:
                db.rollback()
                print(f"DEBUG: VMID {current_vmid} collision in DB, retrying...")
                if payload.vmid:
                    raise HTTPException(status_code=409, detail=f"VMID {payload.vmid} already exists")
                continue
            except Exception as e:
                db.rollback()
                raise e
        
        if not allocated_vmid:
            raise HTTPException(status_code=500, detail="Failed to allocate VMID after retries")
            
        # 3. Update payload with the allocated VMID
        payload.vmid = allocated_vmid
        # -------------------------------------------------------
        
        # Send task to worker
        task = create_vm_task.delay(payload.dict())
        
        return VMActionResponse(
            message="VM creation task queued",
            task_id=task.id
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@app.post("/vms/{vmid}/start", response_model=VMActionResponse)
async def start_vm(
    vmid: int, 
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> VMActionResponse:
    try:
        # Check DB for IB requirement and Ownership
        user_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
        
        # Authorization check
        if user_vm:
            if user_vm.username != user["username"] and user["role"] not in ["admin", "platform_admin"]:
                raise HTTPException(status_code=403, detail="Not authorized to manage this VM")
        
        require_ib = False
        if user_vm:
            if user_vm.ib_count > 0:
                require_ib = True
            # Update status to starting to prevent frequent operations
            user_vm.status = "starting"
            db.commit()

        task = start_vm_task.delay(vmid, require_ib)
        return VMActionResponse(message="VM start task queued", task_id=task.id)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/vms/{vmid}/stop", response_model=VMActionResponse)
async def stop_vm(
    vmid: int, 
    force: bool = False,
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> VMActionResponse:
    try:
        # Check Ownership
        user_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
        if user_vm:
            if user_vm.username != user["username"] and user["role"] not in ["admin", "platform_admin"]:
                raise HTTPException(status_code=403, detail="Not authorized to manage this VM")
            
            # Update status to stopping to prevent frequent operations
            user_vm.status = "stopping"
            db.commit()

        task = stop_vm_task.delay(vmid, force)
        return VMActionResponse(message="VM stop task queued", task_id=task.id)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.delete("/vms/{vmid}", response_model=VMActionResponse)
async def delete_vm(
    vmid: int,
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> VMActionResponse:
    try:
        # Check Ownership
        db_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
        if db_vm:
            if db_vm.username != user["username"] and user["role"] not in ["admin", "platform_admin"]:
                raise HTTPException(status_code=403, detail="Not authorized to delete this VM")
            
            # Update status to deleting
            db_vm.status = "deleting"
            db.commit()

        task = delete_vm_task.delay(vmid)
        return VMActionResponse(message="VM deletion task queued", task_id=task.id)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/vms/{vmid}", response_model=VMStatusResponse)
async def get_vm_status(
    vmid: int, 
    svc: ProxmoxService = Depends(get_service),
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> VMStatusResponse:
    # Ownership check
    user_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
    if user_vm:
        if user_vm.username != user["username"] and user["role"] not in ["admin", "platform_admin"]:
            raise HTTPException(status_code=403, detail="Not authorized to view this VM")

    try:
        result = await run_in_threadpool(svc.get_status, vmid)
        if not isinstance(result, dict):
            raise HTTPException(status_code=502, detail="Unexpected response from Proxmox")

        return VMStatusResponse(
            vmid=vmid,
            name=result.get("name"),
            status=result.get("status", "unknown"),
            qmpstatus=result.get("qmpstatus"),
            info=result,
        )
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/vms/{vmid}/metrics", response_model=VMMetricsResponse)
async def get_vm_metrics(
    vmid: int, 
    timeframe: str = Query("hour", regex="^(hour|day|week|month|year)$"),
    svc: ProxmoxService = Depends(get_service),
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> VMMetricsResponse:
    """
    Returns historical usage metrics for a VM.
    """
    # 1. Ownership check
    user_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
    if user_vm:
        if user_vm.username != user["username"] and user["role"] not in ["admin", "platform_admin"]:
            raise HTTPException(status_code=403, detail="Not authorized to view metrics for this VM")
    
    # 2. Fetch data from PVE
    try:
        data = await run_in_threadpool(svc.get_rrd_data, vmid, timeframe)
        return VMMetricsResponse(vmid=vmid, timeframe=timeframe, data=data)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/vms/{vmid}/firewall", response_model=FirewallResponse)
async def get_vm_firewall(
    vmid: int,
    svc: ProxmoxService = Depends(get_service),
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> FirewallResponse:
    """
    Returns firewall rules for a VM.
    """
    # Ownership check
    user_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
    if user_vm:
        if user_vm.username != user["username"] and user["role"] not in ["admin", "platform_admin"]:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    try:
        rules = await run_in_threadpool(svc.get_firewall_rules, vmid)
        return FirewallResponse(vmid=vmid, rules=rules)
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/vms/{vmid}/firewall", response_model=Dict[str, str])
async def add_vm_firewall_rule(
    vmid: int,
    rule: FirewallRule,
    svc: ProxmoxService = Depends(get_service),
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> Dict[str, str]:
    """
    Adds a firewall rule to a VM.
    """
    # Ownership check
    user_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
    if user_vm:
        if user_vm.username != user["username"] and user["role"] not in ["admin", "platform_admin"]:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    # Normalize port range (replace '-' with ':')
    if rule.dport and "-" in rule.dport:
        rule.dport = rule.dport.replace("-", ":")
    if rule.sport and "-" in rule.sport:
        rule.sport = rule.sport.replace("-", ":")

    # Force log level to info for user-created rules
    rule.log = "info"

    try:
        await run_in_threadpool(svc.add_firewall_rule, vmid, rule.dict(exclude_none=True))
        return {"status": "success", "message": "Firewall rule added"}
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.put("/vms/{vmid}/firewall/{pos}", response_model=Dict[str, str])
async def update_vm_firewall_rule(
    vmid: int,
    pos: int,
    rule: FirewallRule,
    svc: ProxmoxService = Depends(get_service),
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> Dict[str, str]:
    """
    Updates an existing firewall rule.
    Protects rules marked as 'default-prod' or '[LOCKED]'.
    """
    # Ownership check
    user_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
    if user_vm:
        if user_vm.username != user["username"] and user["role"] not in ["admin", "platform_admin"]:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    # Normalize port range (replace '-' with ':')
    if rule.dport and "-" in rule.dport:
        rule.dport = rule.dport.replace("-", ":")
    if rule.sport and "-" in rule.sport:
        rule.sport = rule.sport.replace("-", ":")

    try:
        # Check if rule is locked
        rules = await run_in_threadpool(svc.get_firewall_rules, vmid)
        target_rule = next((r for r in rules if r.get("pos") == pos), None)
        
        if target_rule:
            comment = target_rule.get("comment", "") or ""
            if "default-prod" in comment or "[LOCKED]" in comment:
                raise HTTPException(status_code=403, detail="Cannot modify system default rule")

        await run_in_threadpool(svc.update_firewall_rule, vmid, pos, rule.dict(exclude_none=True))
        return {"status": "success", "message": "Firewall rule updated"}
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.delete("/vms/{vmid}/firewall/{pos}", response_model=Dict[str, str])
async def delete_vm_firewall_rule(
    vmid: int,
    pos: int,
    svc: ProxmoxService = Depends(get_service),
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> Dict[str, str]:
    """
    Deletes a firewall rule from a VM.
    Protects rules marked as 'default-prod' or '[LOCKED]'.
    """
    # Ownership check
    user_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
    if user_vm:
        if user_vm.username != user["username"] and user["role"] not in ["admin", "platform_admin"]:
            raise HTTPException(status_code=403, detail="Not authorized")
    
    try:
        # Check if rule is locked
        rules = await run_in_threadpool(svc.get_firewall_rules, vmid)
        target_rule = next((r for r in rules if r.get("pos") == pos), None)
        
        if target_rule:
            comment = target_rule.get("comment", "") or ""
            if "default-prod" in comment or "[LOCKED]" in comment:
                raise HTTPException(status_code=403, detail="Cannot delete system default rule")

        await run_in_threadpool(svc.delete_firewall_rule, vmid, pos)
        return {"status": "success", "message": "Firewall rule deleted"}
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.post("/vms/{vmid}/firewall/reorder", response_model=Dict[str, str])
async def reorder_vm_firewall_rule(
    vmid: int,
    payload: FirewallReorderRequest,
    svc: ProxmoxService = Depends(get_service),
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> Dict[str, str]:
    """
    Moves a firewall rule to a new priority position.
    """
    # Ownership check
    user_vm = db.query(UserVM).filter(UserVM.vmid == vmid).first()
    if user_vm:
        if user_vm.username != user["username"] and user["role"] not in ["admin", "platform_admin"]:
            raise HTTPException(status_code=403, detail="Not authorized")
            
    try:
        # Check locks for the rule being moved
        rules = await run_in_threadpool(svc.get_firewall_rules, vmid)
        target_rule = next((r for r in rules if r.get("pos") == payload.old_pos), None)
        
        if target_rule:
            comment = target_rule.get("comment", "") or ""
            if "default-prod" in comment or "[LOCKED]" in comment:
                raise HTTPException(status_code=403, detail="Cannot move system default rule")

        await run_in_threadpool(svc.move_firewall_rule, vmid, payload.old_pos, payload.new_pos)
        return {"status": "success", "message": "Firewall rule moved"}
    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/vms", response_model=List[VMSummary])
async def list_vms(
    svc: ProxmoxService = Depends(get_service),
    db: Session = Depends(get_db),
    user: Dict[str, str] = Depends(verify_user),
) -> List[VMSummary]:
    try:
        username = user["username"]
        role = user["role"]

        # 1. Get all VMs from Proxmox (Real-time status)
        all_vms = await run_in_threadpool(svc.list_vms_summary)
        
        # 2. Get all DB records to enrich data
        db_vms = db.query(UserVM).all()
        db_vm_map = {vm.vmid: vm for vm in db_vms}

        enriched_vms = []
        updates_made = False
        found_vmid_in_pve = set()

        for vm in all_vms:
            if vm.vmid in db_vm_map:
                record = db_vm_map[vm.vmid]
                found_vmid_in_pve.add(vm.vmid)
                
                # Sync status and IP from Proxmox to DB
                # Preserve transient states to prevent UI flickering
                db_status = record.status
                
                # If DB says deleted, trust it and hide the VM even if PVE sees it (e.g. deletion lag)
                if db_status == "deleted":
                    continue

                pve_status = vm.status
                should_update_status = False

                if db_status == "starting":
                    if pve_status == "running":
                        # Wait for Celery task to confirm startup via Ping
                        should_update_status = False
                elif db_status == "stopping":
                    if pve_status == "stopped":
                        should_update_status = True
                elif db_status in ["creating", "deleting", "deleted"]:
                    # Keep these statuses until the task explicitly updates the DB
                    should_update_status = False
                elif db_status != pve_status:
                    should_update_status = True

                if should_update_status:
                    record.status = pve_status
                    updates_made = True
                else:
                    # Return the DB status (e.g., starting) to frontend instead of raw PVE status
                    vm.status = record.status
                
                if record.ip_address != vm.ip:
                    record.ip_address = vm.ip
                    updates_made = True

                # Override specs from DB source of truth
                vm.name = record.vm_name  # Force use of DB name to prevent flickering
                vm.vm_username = record.vm_username
                vm.gpu_count = record.gpu_count
                vm.ib_count = record.ib_count
                if record.cpu_cores:
                    vm.cpu_cores = record.cpu_cores
                if record.memory_mb:
                    vm.memory_mb = record.memory_mb
                if record.storage_gb:
                    vm.storage_size_gb = record.storage_gb
                
                enriched_vms.append(vm)

        # Add VMs that are in DB but NOT in PVE (e.g. creating/queued)
        for vmid, record in db_vm_map.items():
            if vmid not in found_vmid_in_pve:
                # SKIP deleted VMs so they don't show up in the frontend
                if record.status == "deleted":
                    continue
                
                enriched_vms.append(
                    VMSummary(
                        vmid=vmid,
                        name=record.vm_name,
                        vm_username=record.vm_username,
                        node="pending",
                        status=record.status or "creating",
                        storage_size_gb=record.storage_gb,
                        ip=record.ip_address or "pending",
                        cpu_cores=record.cpu_cores or 0,
                        memory_mb=record.memory_mb or 0,
                        gpu_count=record.gpu_count or 0,
                        ib_count=record.ib_count or 0,
                    )
                )

        if updates_made:
            db.commit()

        # 3. Filter based on permissions
        if role in ["admin", "platform_admin"]:
            return enriched_vms
        
        if not username:
            return []

        # 4. Filter by username
        user_vmids = {vmid for vmid, record in db_vm_map.items() if record.username == username}
        filtered_vms = [vm for vm in enriched_vms if vm.vmid in user_vmids]
        return filtered_vms

    except RuntimeError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

