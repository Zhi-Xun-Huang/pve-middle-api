import contextlib
import fcntl
import ipaddress
import os
import re
import subprocess
import urllib.parse
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from proxmoxer import ProxmoxAPI  # type: ignore

from .config import Settings
from .schemas import VMCreateRequest, VMSummary


GPU_RESOURCES = [f"GPU{i}" for i in range(8)]
IB_RESOURCES = [f"IB{i}" for i in range(8)]


class ProxmoxService:
    """Thin wrapper around proxmoxer to keep route handlers tidy."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        try:
            self.client = ProxmoxAPI(
                settings.proxmox_host,
                user=settings.proxmox_user,
                token_name=settings.proxmox_token_name,
                token_value=settings.proxmox_token_value,
                verify_ssl=settings.proxmox_verify_ssl,
                port=settings.proxmox_port,
                timeout=settings.proxmox_timeout,
            )
        except Exception as exc:  # pragma: no cover - init-time failure
            raise RuntimeError(f"Failed to initialize Proxmox client: {exc}") from exc

    def _call(self, action: Callable[[], Any], context: str) -> Any:
        try:
            return action()
        except Exception as exc:
            raise RuntimeError(f"PVE {context} failed: {exc}") from exc

    @contextlib.contextmanager
    def _ip_lock(self) -> Any:
        lock_path = self.settings.ip_lock_file
        os.makedirs(os.path.dirname(lock_path), exist_ok=True)
        with open(lock_path, "a+", encoding="utf-8") as lock_file:
            fcntl.flock(lock_file, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock_file, fcntl.LOCK_UN)

    def _find_node_for_vmid(self, vmid: int) -> str:
        resources = self._call(
            lambda: self.client.cluster.resources.get(type="vm"),
            "discover VM location",
        )
        for res in resources:
            if res.get("vmid") == vmid:
                node = res.get("node")
                if node:
                    return node
        raise RuntimeError(f"VM {vmid} not found on any node")

    def _list_vms_on_node(self, node: str) -> List[Dict[str, Any]]:
        return self._call(lambda: self.client.nodes(node).qemu.get(), f"list VMs on node {node}")

    def _get_vm_config(self, node: str, vmid: int) -> Dict[str, Any]:
        return self._call(lambda: self.client.nodes(node).qemu(vmid).config.get(), f"get config for {vmid} on {node}")

    def _cluster_nodes(self) -> Set[str]:
        nodes_resp = self._call(lambda: self.client.nodes.get(), "list nodes")
        return {n["node"] for n in nodes_resp if "node" in n}

    def _vmids_on_node(self, node: str, statuses: Optional[Set[str]] = None) -> List[int]:
        resources = self._call(lambda: self.client.cluster.resources.get(type="vm"), "list VMs")
        result: List[int] = []
        for res in resources:
            if res.get("node") != node:
                continue
            if statuses and res.get("status") not in statuses:
                continue
            if "vmid" in res:
                result.append(int(res["vmid"]))
        return result

    def _wait_for_task(self, node: str, upid: str, timeout: int = 600, interval: int = 3) -> Dict[str, Any]:
        import time

        end = time.time() + timeout
        while time.time() < end:
            status = self._call(lambda: self.client.nodes(node).tasks(upid).status.get(), f"poll task {upid}")
            if status.get("status") == "stopped":
                return status
            time.sleep(interval)
        raise RuntimeError(f"Task {upid} did not finish within {timeout}s")

    def _wait_for_config(self, node: str, vmid: int, timeout: int = 120, interval: int = 3) -> Dict[str, Any]:
        import time

        end = time.time() + timeout
        last_exc: Optional[Exception] = None
        while time.time() < end:
            try:
                return self._get_vm_config(node, vmid)
            except Exception as exc:
                last_exc = exc
                time.sleep(interval)
        if last_exc:
            raise RuntimeError(f"Config for VM {vmid} not available after clone: {last_exc}") from last_exc
        raise RuntimeError(f"Config for VM {vmid} not available after clone")

    def get_next_id(self) -> int:
        nextid = self._call(lambda: self.client.cluster.nextid.get(), "fetch next VMID")
        return int(nextid)

    @staticmethod
    def _parse_hostpci_from_config(config: Dict[str, Any]) -> Set[str]:
        devices: Set[str] = set()
        pattern = re.compile(r"hostpci\d+")
        for key, value in config.items():
            if pattern.fullmatch(key) and isinstance(value, str):
                parts = [p.strip() for p in value.split(",") if p.strip()]
                target = None
                for p in parts:
                    if p.startswith("mapping="):
                        target = p.split("=", 1)[1]
                        break
                    if p.startswith("host="):
                        target = p.split("=", 1)[1]
                        break
                    if p.startswith("resource="):
                        target = p.split("=", 1)[1]
                        break
                if not target and parts:
                    target = parts[0]
                if target:
                    devices.add(target)
        return devices

    def _used_ips(self) -> Set[str]:
        used: Set[str] = set()
        resources = self._call(lambda: self.client.cluster.resources.get(type="vm"), "list VMs for IP scan")
        for res in resources:
            node = res.get("node")
            vmid = res.get("vmid")
            if not node or vmid is None:
                continue
            config = self._get_vm_config(node, int(vmid))
            ipconf = config.get("ipconfig0")
            if not ipconf or not isinstance(ipconf, str):
                continue
            for part in ipconf.split(","):
                if part.strip().startswith("ip="):
                    ip = part.split("=", 1)[1]
                    if "/" in ip:
                        used.add(ip.split("/")[0])
                    else:
                        used.add(ip)
        return used

    def ping_ip(self, ip: str) -> bool:
        timeout_flag = max(1, int(self.settings.ip_ping_timeout_ms / 1000))
        cmd = ["ping", "-c", "1", "-W", str(timeout_flag), ip]
        try:
            result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            return result.returncode == 0
        except Exception:
            return False

    def is_port_open(self, ip: str, port: int, timeout: float = 1.0) -> bool:
        """Checks if a TCP port is open on the target IP."""
        import socket
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _probe_subnet_alive(self, network: ipaddress._BaseNetwork) -> Set[str]:
        alive: Set[str] = set()
        if not self.settings.ip_ping_sweep:
            return alive
        for host in network.hosts():
            ip = str(host)
            if self.ping_ip(ip):
                alive.add(ip)
        return alive

    def _allocate_ip(self, use_public: bool = False, ip_pools: List[Dict[str, Any]] = None) -> Tuple[str, str, str]:
        # Filter pools by type
        target_type = "public" if use_public else "private"
        candidate_pools = []
        
        if ip_pools:
            candidate_pools = [p for p in ip_pools if p.get("type") == target_type]
        
        # Fallback to legacy env if no pools provided/found (Maintenance/Migration path)
        if not candidate_pools:
            network = ipaddress.ip_network(self.settings.ip_pool_cidr, strict=False)
            # Create a virtual pool from legacy settings for backward compatibility
            fallback_pool = {
                "start_ip": str(network.network_address + 10),
                "end_ip": str(network.network_address + 33),
                "gateway": self.settings.ip_gateway,
                "cidr": str(network.prefixlen),
                "type": "private" # Legacy is always private
            }
            if not use_public:
                candidate_pools.append(fallback_pool)

        if not candidate_pools:
             raise RuntimeError(f"No IP pools defined for type '{target_type}'")

        with self._ip_lock():
            used = self._used_ips()
            
            # Iterate over each pool until we find an IP
            for pool in candidate_pools:
                try:
                    s_obj = ipaddress.IPv4Address(pool["start_ip"])
                    e_obj = ipaddress.IPv4Address(pool["end_ip"])
                    gateway = pool.get("gateway")
                    cidr = pool.get("cidr", "24")
                    
                    curr = int(s_obj)
                    limit = int(e_obj)
                    
                    while curr <= limit:
                        ip_str = str(ipaddress.IPv4Address(curr))
                        
                        if ip_str not in used and ip_str != gateway:
                            if not (self.settings.ip_ping_sweep and self._ping_ip(ip_str)):
                                return ip_str, str(cidr), gateway or ""
                        
                        curr += 1
                except ValueError:
                    print(f"Warning: Invalid IP range in pool {pool}")
                    continue

        raise RuntimeError(f"No available IPs in any {target_type} pool")

    def _update_hostpci(self, node: str, vmid: int, gpus: List[str], ibs: List[str]) -> None:
        params: Dict[str, Any] = {}
        for idx, gpu in enumerate(gpus):
            params[f"hostpci{idx}"] = f"mapping={gpu},pcie=1"
        for j, ib in enumerate(ibs):
            params[f"hostpci{len(gpus) + j}"] = f"mapping={ib},pcie=1"

        config = self._get_vm_config(node, vmid)
        pattern = re.compile(r"hostpci(\d+)")
        delete_keys: List[str] = []
        for key in config.keys():
            m = pattern.fullmatch(key)
            if m:
                idx = int(m.group(1))
                if idx >= len(gpus) + len(ibs):
                    delete_keys.append(key)
        if delete_keys:
            params["delete"] = ",".join(delete_keys)

        if params:
            self._call(
                lambda: self.client.nodes(node).qemu(vmid).config.post(**params),
                f"update hostpci for VM {vmid}",
            )

    def _migrate_vm_offline(self, source_node: str, target_node: str, vmid: int) -> None:
        migrate_params = {"target": target_node, "online": 0, "with-local-disks": 1}
        result = self._call(
            lambda: self.client.nodes(source_node).qemu(vmid).migrate.post(**migrate_params),
            f"migrate VM {vmid} from {source_node} to {target_node}",
        )
        upid = result.get("data") if isinstance(result, dict) else None
        if upid:
            self._wait_for_task(source_node, upid, timeout=1800, interval=5)

    def _used_pci_devices(self, node: str, statuses: Optional[Set[str]] = None) -> Set[str]:
        assigned: Set[str] = set()
        for vmid in self._vmids_on_node(node, statuses=statuses):
            config = self._get_vm_config(node, vmid)
            assigned |= self._parse_hostpci_from_config(config)
        return assigned

    def _available_pci_devices(self, node: str, mapping: List[str], statuses: Optional[Set[str]] = None) -> List[str]:
        assigned = self._used_pci_devices(node, statuses=statuses)
        return [dev for dev in mapping if dev not in assigned]

    @staticmethod
    def _pair_devices(available_gpus: List[str], available_ibs: List[str], needed: int, require_ib: bool) -> Tuple[List[str], List[str]]:
        if not require_ib:
            return available_gpus[:needed], []

        def idx(name: str) -> Optional[int]:
            m = re.search(r"(\d+)$", name)
            return int(m.group(1)) if m else None

        gpu_by_idx = {idx(g): g for g in available_gpus if idx(g) is not None}
        ib_by_idx = {idx(i): i for i in available_ibs if idx(i) is not None}

        paired_gpus: List[str] = []
        paired_ibs: List[str] = []
        for i in sorted(gpu_by_idx.keys()):
            if len(paired_gpus) >= needed:
                break
            if i in ib_by_idx:
                paired_gpus.append(gpu_by_idx[i])
                paired_ibs.append(ib_by_idx[i])

        if len(paired_gpus) < needed:
            raise RuntimeError(f"Not enough matching GPU/IB pairs; needed {needed}, found {len(paired_gpus)}")

        return paired_gpus, paired_ibs

    @staticmethod
    def _prioritize_devices(available: List[str], preferred: List[str]) -> List[str]:
        preferred_set = set(preferred)
        ordered: List[str] = [dev for dev in preferred if dev in available]
        ordered.extend([dev for dev in available if dev not in preferred_set])
        return ordered

    @staticmethod
    def _hostpci_entries(config: Dict[str, Any]) -> Tuple[List[str], List[str]]:
        gpu_entries: List[str] = []
        ib_entries: List[str] = []
        pattern = re.compile(r"hostpci\d+")
        for key, value in config.items():
            if not pattern.fullmatch(key) or not isinstance(value, str):
                continue
            target = None
            for part in value.split(","):
                part = part.strip()
                if part.startswith("mapping=") or part.startswith("host=") or part.startswith("resource="):
                    target = part.split("=", 1)[1]
                    break
            if not target:
                target = value.split(",", 1)[0].strip()
            if target.startswith("GPU"):
                gpu_entries.append(target)
            elif target.startswith("IB"):
                ib_entries.append(target)
        return gpu_entries, ib_entries

    @staticmethod
    def _parse_disk_size_gb(config: Dict[str, Any], disk_key: str = "scsi0") -> Optional[float]:
        disk = config.get(disk_key)
        if not isinstance(disk, str):
            return None
        parts = disk.split(",")
        for p in parts:
            if p.startswith("size="):
                size_str = p.split("=", 1)[1]
                try:
                    if size_str.endswith("G"):
                        return float(size_str[:-1])
                    if size_str.endswith("M"):
                        return float(size_str[:-1]) / 1024
                    if size_str.endswith("K"):
                        return float(size_str[:-1]) / (1024 * 1024)
                except ValueError:
                    return None
        return None

    @staticmethod
    def _parse_ip_from_config(config: Dict[str, Any]) -> Optional[str]:
        ipconf = config.get("ipconfig0")
        if not isinstance(ipconf, str):
            return None
        for part in ipconf.split(","):
            part = part.strip()
            if part.startswith("ip="):
                ip_part = part.split("=", 1)[1]
                return ip_part.split("/")[0]
        return None

    def get_vm_profile(self, profile_id: int) -> Dict[str, Any]:
        profiles = {
            1: {"name": "basic", "cores": 12, "memory_mb": 196_608, "gpus": 1},
            2: {"name": "standard", "cores": 24, "memory_mb": 393_216, "gpus": 2},
            3: {"name": "premium", "cores": 48, "memory_mb": 786_432, "gpus": 4},
            4: {"name": "ultra", "cores": 96, "memory_mb": 1572_864, "gpus": 8},
        }
        profile = profiles.get(profile_id)
        if not profile:
            raise RuntimeError(f"Unknown vm_profile {profile_id}")
        return profile

    @staticmethod
    def _infer_profile(cores: int, memory_mb: int) -> Optional[int]:
        profiles = {
            1: {"cores": 12, "memory_mb": 196_608},
            2: {"cores": 24, "memory_mb": 393_216},
            3: {"cores": 48, "memory_mb": 786_432},
            4: {"cores": 96, "memory_mb": 1572_864}
        }
        for pid, vals in profiles.items():
            if cores == vals["cores"] and memory_mb == vals["memory_mb"]:
                return pid
        return None

    def _select_node_and_devices(self, profile: Dict[str, Any], require_ib: bool) -> Tuple[str, List[str], List[str]]:
        candidate_nodes = sorted(self._cluster_nodes())
        needed_gpus = profile["gpus"]
        diagnostics: List[str] = []

        for node in candidate_nodes:
            available_gpus = self._available_pci_devices(node, GPU_RESOURCES)
            available_ibs = self._available_pci_devices(node, IB_RESOURCES) if require_ib else []

            pair_info = ""
            if require_ib:
                try:
                    paired_gpus, _ = self._pair_devices(available_gpus, available_ibs, needed_gpus, True)
                    pair_info = f", pairs={len(paired_gpus)}"
                except RuntimeError:
                    pair_info = ", pairs=0"
            diagnostics.append(
                f"{node}: gpu_avail={len(available_gpus)}, ib_avail={len(available_ibs)}{pair_info}"
            )

            if len(available_gpus) < needed_gpus:
                continue
            if require_ib and len(available_ibs) < needed_gpus:
                continue

            try:
                selected_gpus, selected_ib = self._pair_devices(available_gpus, available_ibs, needed_gpus, require_ib)
            except RuntimeError:
                continue
            return node, selected_gpus, selected_ib

        diag_msg = "; ".join(diagnostics) if diagnostics else "no nodes discovered"
        raise RuntimeError(f"No node found with sufficient GPU/IB resources (needed GPUs={needed_gpus}, IB={require_ib}); availability: {diag_msg}")

    def _plan_allocation_for_existing_vm(
        self,
        current_node: str,
        needed_gpus: int,
        require_ib: bool,
        preferred_gpus: List[str],
        preferred_ibs: List[str],
    ) -> Tuple[str, List[str], List[str]]:
        nodes = [current_node] + [n for n in sorted(self._cluster_nodes()) if n != current_node]
        diagnostics: List[str] = []

        for node in nodes:
            available_gpus = self._available_pci_devices(node, GPU_RESOURCES)
            available_ibs = self._available_pci_devices(node, IB_RESOURCES) if require_ib else []

            available_gpus = self._prioritize_devices(available_gpus, preferred_gpus)
            if require_ib:
                available_ibs = self._prioritize_devices(available_ibs, preferred_ibs)

            pair_info = ""
            if require_ib:
                try:
                    paired_gpus, _ = self._pair_devices(available_gpus, available_ibs, needed_gpus, True)
                    pair_info = f", pairs={len(paired_gpus)}"
                except RuntimeError:
                    pair_info = ", pairs=0"
            diagnostics.append(
                f"{node}: gpu_avail={len(available_gpus)}, ib_avail={len(available_ibs)}{pair_info}"
            )

            if len(available_gpus) < needed_gpus:
                continue
            if require_ib and len(available_ibs) < needed_gpus:
                continue

            try:
                selected_gpus, selected_ibs = self._pair_devices(available_gpus, available_ibs, needed_gpus, require_ib)
            except RuntimeError:
                continue
            return node, selected_gpus, selected_ibs

        diag_msg = "; ".join(diagnostics) if diagnostics else "no nodes discovered"
        raise RuntimeError(
            f"No node found for VM start with GPUs={needed_gpus}, IB={require_ib}; availability: {diag_msg}"
        )

    def _add_ip_to_ipfilter(self, node: str, vmid: int, ip: str) -> None:
        try:
            # Add IP to ipfilter-net0 IPSet
            # Note: We append /32 (or /128 for IPv6) implicitly by passing just the IP, 
            # or we can pass explicit CIDR. PVE accepts IP address.
            self._call(
                lambda: self.client.nodes(node).qemu(vmid).firewall.ipset("ipfilter-net0").post(cidr=ip),
                f"add {ip} to ipfilter-net0 for VM {vmid}"
            )
        except Exception as e:
            # Log warning but don't fail creation if firewall setup fails (unless critical)
            print(f"Warning: Failed to update ipfilter-net0 for VM {vmid}: {e}")

    def create_vm(self, payload: VMCreateRequest, ip_pools: List[Dict[str, Any]] = None) -> Dict[str, Any]:
        profile = self.get_vm_profile(payload.vm_profile)
        vmid = payload.vmid or self.get_next_id()
        ip, cidr_suffix, gateway = self._allocate_ip(payload.use_public_ip, ip_pools)
        ipconfig0 = f"ip={ip}/{cidr_suffix},gw={gateway}"
        nameserver = self.settings.ip_dns

        node_hint = payload.node or self.settings.proxmox_node
        cluster_nodes = self._cluster_nodes()
        fallback_note: Optional[str] = None
        if node_hint and node_hint not in cluster_nodes:
            fallback_note = f"Provided node '{node_hint}' not in cluster; auto-selected instead."
            node_hint = None

        # Dynamic Allocation: We just select a node here, but DO NOT reserve/assign GPUs yet.
        # Assignment happens at start_vm.
        if node_hint:
            node = node_hint
        else:
            # Try to find a node that *currently* has resources, just as a hint for placement.
            # But we don't strictly enforce reservation here.
            try:
                node, _, _ = self._select_node_and_devices(profile, payload.required_ib)
            except RuntimeError:
                # If no node has resources NOW, pick a random capable node or the first one.
                # For simplicity, let's pick the one with most free RAM or just the first one.
                # Here we just fallback to the first available node to allow creation even if full.
                node = sorted(list(cluster_nodes))[0]

        template_node = self._find_node_for_vmid(payload.vm_template)

        clone_params = {
            "newid": vmid,
            "name": payload.vm_name,
            "target": node,
            "full": 1,
            "storage": self.settings.storage_name,
        }
        clone_result = self._call(
            lambda: self.client.nodes(template_node).qemu(payload.vm_template).clone.post(**clone_params),
            f"clone template {payload.vm_template} to {vmid}",
        )
        clone_upid = clone_result.get("data") if isinstance(clone_result, dict) else None
        if clone_upid:
            self._wait_for_task(node, clone_upid, timeout=1800, interval=5)
        
        # Give PVE a moment to release the lock after clone task status says "stopped"
        import time
        time.sleep(3)

        self._wait_for_config(node, vmid, timeout=180, interval=5)

        config_params: Dict[str, Any] = {
            "cores": profile["cores"],
            "sockets": 1,
            "memory": profile["memory_mb"],
            "ciuser": payload.username,
            "cipassword": payload.password,
            "ipconfig0": ipconfig0,
            "nameserver": nameserver,
            "scsihw": "virtio-scsi-pci",
        }

        if payload.ssh_public_key:
            # Proxmox expects the key to be URL-encoded, but proxmoxer/requests handles encoding of parameters.
            # However, PVE stores sshkeys as a URL-encoded string in the config file.
            # We must encode it ourselves so PVE receives the encoded string.
            # We also set safe='' to ensure characters like '/' are encoded, preventing issues with PVE's handling.
            config_params["sshkeys"] = urllib.parse.quote(payload.ssh_public_key, safe='')

        # ensure cloud-init drive present
        config_params["ide2"] = f"{self.settings.storage_name}:cloudinit"

        # DYNAMIC ALLOCATION: Do NOT assign hostpci here.
        # We leave the VM without GPUs. They will be assigned on start_vm.

        # Retry configuration if locked
        max_retries = 10
        for attempt in range(max_retries):
            try:
                config_result = self._call(
                    lambda: self.client.nodes(node).qemu(vmid).config.post(**config_params),
                    f"configure VM {vmid}",
                )
                break
            except RuntimeError as e:
                if "can't lock file" in str(e) and attempt < max_retries - 1:
                    print(f"VM {vmid} locked, retrying config in 3s... ({attempt + 1}/{max_retries})")
                    time.sleep(3)
                else:
                    raise e

        # Retry resize if locked (though unlikely if config passed)
        for attempt in range(max_retries):
            try:
                resize_task = self._call(
                    lambda: self.client.nodes(node).qemu(vmid).resize.put(disk="scsi0", size=f"{payload.storage_size}G"),
                    f"resize disk for VM {vmid}",
                )
                break
            except RuntimeError as e:
                if "can't lock file" in str(e) and attempt < max_retries - 1:
                    print(f"VM {vmid} locked, retrying resize in 3s... ({attempt + 1}/{max_retries})")
                    time.sleep(3)
                else:
                    raise e

        # Update IPSet ipfilter-net0 to lock source IP
        self._add_ip_to_ipfilter(node, vmid, ip)

        return {
            "vmid": vmid,
            "node": node,
            "ip": ip,
            "clone": clone_result,
            "config": config_result,
            "resize": resize_task,
            "profile": profile,
            "gpus": [], # No GPUs assigned at creation
            "ibs": [],  # No IBs assigned at creation
            "note": fallback_note,
        }

    def list_vms_summary(self) -> List[VMSummary]:
        summaries: List[VMSummary] = []
        resources = self._call(lambda: self.client.cluster.resources.get(type="vm"), "list VMs")
        for res in resources:
            vmid = res.get("vmid")
            node = res.get("node")
            name = res.get("name")
            status = res.get("status", "unknown")
            if vmid is None or node is None:
                continue
            vmid_int = int(vmid)
            config = self._get_vm_config(node, vmid_int)
            storage_size = self._parse_disk_size_gb(config)
            ip_addr = self._parse_ip_from_config(config)
            cores = int(config.get("cores", 0))
            memory_mb = int(config.get("memory", 0))
            profile_id = self._infer_profile(cores, memory_mb)
            hostpcis = self._parse_hostpci_from_config(config)
            gpu_count = sum(1 for dev in hostpcis if "GPU" in dev or "NVIDIA" in dev or dev in GPU_RESOURCES)
            required_ib = any(dev.startswith("IB") for dev in hostpcis)
            summaries.append(
                VMSummary(
                    vmid=vmid_int,
                    name=name,
                    node=node,
                    status=status,
                    storage_size_gb=storage_size,
                    ip=ip_addr,
                    cpu_cores=cores,
                    memory_mb=memory_mb,
                    gpu_count=gpu_count,
                    vm_profile=profile_id,
                    required_ib=required_ib,
                )
            )
        return summaries

    def start_vm(
        self, 
        vmid: int, 
        require_ib: bool = False, 
        cpu_cores: Optional[int] = None, 
        memory_mb: Optional[int] = None,
        gpu_count: Optional[int] = None,
        ipconfig0: Optional[str] = None
    ) -> Dict[str, Any]:
        node = self._find_node_for_vmid(vmid)
        config = self._get_vm_config(node, vmid)

        # 1. Sync Resource Specs (CPU/Memory/Network) if provided
        config_updates: Dict[str, Any] = {}
        if cpu_cores is not None:
            current_cores = int(config.get("cores", 0))
            if cpu_cores != current_cores:
                config_updates["cores"] = cpu_cores
        
        if memory_mb is not None:
            current_mem = int(config.get("memory", 0))
            if memory_mb != current_mem:
                config_updates["memory"] = memory_mb
        
        if ipconfig0 is not None:
            # Always apply ipconfig0 if provided to ensure consistency/regeneration
            config_updates["ipconfig0"] = ipconfig0
        
        if config_updates:
            self._call(
                lambda: self.client.nodes(node).qemu(vmid).config.post(**config_updates),
                f"update VM specs for {vmid}"
            )
            # Refresh config after update
            config = self._get_vm_config(node, vmid)

        # 2. Resource Allocation (GPU/IB)
        preferred_gpus, preferred_ibs = self._hostpci_entries(config)
        
        # Determine needed GPUs: use explicit count if provided, otherwise infer from config/profile
        if gpu_count is not None:
            needed_gpus = gpu_count
        else:
            needed_gpus = len(preferred_gpus)
            if needed_gpus == 0:
                profile_id = self._infer_profile(int(config.get("cores", 0)), int(config.get("memory", 0)))
                if profile_id:
                    needed_gpus = self.get_vm_profile(profile_id)["gpus"]

        current_require_ib = len(preferred_ibs) > 0 or require_ib

        if needed_gpus > 0:
            target_node, gpus, ibs = self._plan_allocation_for_existing_vm(
                node,
                needed_gpus,
                current_require_ib,
                preferred_gpus,
                preferred_ibs,
            )
            if target_node != node:
                self._migrate_vm_offline(node, target_node, vmid)
                import time
                time.sleep(3) # Wait for cluster sync
                node = self._find_node_for_vmid(vmid)
            
            self._update_hostpci(node, vmid, gpus, ibs)
        
        # If gpu_count is 0 but there are leftover PCI devices, we should clear them?
        # The original code didn't handle scaling DOWN to 0 GPUs explicitly on start, 
        # but stop_vm handles cleanup. 
        # For now, we assume _update_hostpci handles re-mapping, but we might need to handle 
        # the case where needed_gpus is 0 but config has hostpci entries.
        if needed_gpus == 0:
            # Check if we need to clean up existing GPU passthrough
            pattern = re.compile(r"hostpci\d+")
            delete_keys = [k for k in config.keys() if pattern.fullmatch(k)]
            if delete_keys:
                self._call(
                    lambda: self.client.nodes(node).qemu(vmid).config.post(delete=",".join(delete_keys)),
                    f"remove unneeded hostpci for VM {vmid}"
                )

        return self._call(lambda: self.client.nodes(node).qemu(vmid).status.start.post(), "start VM")

    def stop_vm(self, vmid: int, force: bool = False) -> Dict[str, Any]:
        node = self._find_node_for_vmid(vmid)
        if force:
            res = self._call(
                lambda: self.client.nodes(node).qemu(vmid).status.stop.post(),
                "stop VM (force)",
            )
        else:
            res = self._call(
                lambda: self.client.nodes(node).qemu(vmid).status.shutdown.post(),
                "shutdown VM",
            )
        
        # Release Resources (Dynamic Allocation)
        # For Hard Stop (force=True), this usually succeeds immediately.
        # For Soft Shutdown, this might fail if VM is not yet stopped, but we attempt it anyway.
        try:
            config = self._get_vm_config(node, vmid)
            delete_keys = []
            pattern = re.compile(r"hostpci\d+")
            for key in config.keys():
                if pattern.fullmatch(key):
                    delete_keys.append(key)
            
            if delete_keys:
                self._call(
                    lambda: self.client.nodes(node).qemu(vmid).config.post(delete=",".join(delete_keys)),
                    f"release resources for VM {vmid}",
                )
        except Exception as e:
            print(f"Warning: Failed to release resources for {vmid} (force={force}): {e}")
            
        return res

    def delete_vm(self, vmid: int) -> Dict[str, Any]:
        node = self._find_node_for_vmid(vmid)
        return self._call(
            lambda: self.client.nodes(node).qemu(vmid).delete(),
            "delete VM",
        )

    def get_status(self, vmid: int) -> Dict[str, Any]:
        node = self._find_node_for_vmid(vmid)
        return self._call(
            lambda: self.client.nodes(node).qemu(vmid).status.current.get(),
            "get VM status",
        )

    def get_rrd_data(self, vmid: int, timeframe: str = "hour") -> List[Dict[str, Any]]:
        node = self._find_node_for_vmid(vmid)
        return self._call(
            lambda: self.client.nodes(node).qemu(vmid).rrddata.get(timeframe=timeframe),
            f"get RRD data for {vmid}"
        )

    def get_firewall_rules(self, vmid: int) -> List[Dict[str, Any]]:
        node = self._find_node_for_vmid(vmid)
        return self._call(
            lambda: self.client.nodes(node).qemu(vmid).firewall.rules.get(),
            f"get firewall rules for {vmid}"
        )

    def add_firewall_rule(self, vmid: int, rule: Dict[str, Any]) -> None:
        node = self._find_node_for_vmid(vmid)
        # Ensure firewall is enabled first
        self.ensure_firewall_enabled(vmid)
        self._call(
            lambda: self.client.nodes(node).qemu(vmid).firewall.rules.post(**rule),
            f"add firewall rule for {vmid}"
        )

    def update_firewall_rule(self, vmid: int, pos: int, rule: Dict[str, Any]) -> None:
        node = self._find_node_for_vmid(vmid)
        # Remove 'pos' from payload if present, as it's in the URL
        rule.pop("pos", None)
        self._call(
            lambda: self.client.nodes(node).qemu(vmid).firewall.rules(pos).put(**rule),
            f"update firewall rule {pos} for {vmid}"
        )

    def delete_firewall_rule(self, vmid: int, pos: int) -> None:
        node = self._find_node_for_vmid(vmid)
        self._call(
            lambda: self.client.nodes(node).qemu(vmid).firewall.rules(pos).delete(),
            f"delete firewall rule {pos} for {vmid}"
        )

    def move_firewall_rule(self, vmid: int, old_pos: int, new_pos: int) -> None:
        """
        Moves a firewall rule by SWAPPING the positions of two rules in the list,
        and then doing a full re-create.
        """
        if old_pos == new_pos:
            return

        node = self._find_node_for_vmid(vmid)
        
        # 1. Get all rules and sort them explicitly by pos
        raw_rules = self.get_firewall_rules(vmid)
        # Sort strictly by pos to align with list indices
        rules = sorted(raw_rules, key=lambda x: int(x.get("pos", 0)))
        
        # 2. Find list indices for the source and target POS
        old_index = next((i for i, r in enumerate(rules) if int(r.get("pos", -1)) == old_pos), None)
        new_index = next((i for i, r in enumerate(rules) if int(r.get("pos", -1)) == new_pos), None)
        
        if old_index is None:
            raise RuntimeError(f"Firewall rule at pos {old_pos} not found")
        if new_index is None:
            raise RuntimeError(f"Target firewall rule at pos {new_pos} not found")
            
        print(f"DEBUG REORDER: Swapping index {old_index} (pos {old_pos}) with index {new_index} (pos {new_pos})")
        
        # 3. Swap elements in the list
        rules[old_index], rules[new_index] = rules[new_index], rules[old_index]
        final_ordered_rules = rules
        
        print(f"DEBUG REORDER: Final Order: {[int(r.get('pos', -1)) for r in final_ordered_rules]}")
            
        # 4. Delete ALL existing rules from Proxmox (Reverse Order)
        rules_to_delete = sorted(raw_rules, key=lambda x: int(x.get("pos", 0)), reverse=True)
        for r in rules_to_delete:
            p = int(r["pos"])
            self._call(
                lambda: self.client.nodes(node).qemu(vmid).firewall.rules(p).delete(),
                f"cleanup rule {p}"
            )
            
        # 5. Restore all rules in the new sequence
        # CRITICAL: We REVERSE the sequence during POST because PVE's POST API 
        # prepends new rules to position 0 by default. By posting the last rule first,
        # it will end up at the bottom, and the first rule (posted last) will be at pos 0.
        for rule in reversed(final_ordered_rules):
            # Prepare clean payload
            payload = {k: v for k, v in rule.items() if v is not None}
            payload.pop("pos", None)
            payload.pop("ipversion", None)
            payload.pop("digest", None)
            
            # Ensure user-created rules (not marked 'default') have log level set to info
            if not (payload.get("comment") or "").lower().__contains__("default"):
                payload["log"] = "info"
            
            self._call(
                lambda: self.client.nodes(node).qemu(vmid).firewall.rules.post(**payload),
                f"restore rule (original pos: {rule.get('pos')})"
            )

    def ensure_firewall_enabled(self, vmid: int) -> None:
        """Ensures VM-level firewall and net0 interface firewall are both ON."""
        node = self._find_node_for_vmid(vmid)
        
        # 1. Enable VM Firewall Options (Global for VM)
        # Use firewall/options endpoint, parameter is 'enable'
        try:
            self._call(
                lambda: self.client.nodes(node).qemu(vmid).firewall.options.put(enable=1),
                f"enable firewall option for {vmid}"
            )
        except Exception as e:
            print(f"Warning: Failed to enable firewall option for {vmid}: {e}")

        # 2. Check net0 interface firewall toggle (in config)
        config = self._get_vm_config(node, vmid)
        updates = {}
        net0 = config.get("net0", "")
        if "firewall=1" not in net0:
            # Append firewall=1 to net0 string
            if net0:
                updates["net0"] = f"{net0},firewall=1"
        
        if updates:
            self._call(
                lambda: self.client.nodes(node).qemu(vmid).config.post(**updates),
                f"enable firewall on net0 for {vmid}"
            )

    def check_ip_availability(self, use_public: bool, ip_pools: List[Dict[str, Any]] = None) -> bool:
        """
        Checks if there is at least one available IP in the specified pools.
        Returns True if available, False otherwise.
        """
        # Filter pools by type
        target_type = "public" if use_public else "private"
        candidate_pools = []
        
        if ip_pools:
            candidate_pools = [p for p in ip_pools if p.get("type") == target_type]
        
        # Fallback to legacy env
        if not candidate_pools:
            network = ipaddress.ip_network(self.settings.ip_pool_cidr, strict=False)
            fallback_pool = {
                "start_ip": str(network.network_address + 10),
                "end_ip": str(network.network_address + 33),
                "gateway": self.settings.ip_gateway,
                "cidr": str(network.prefixlen),
                "type": "private"
            }
            if not use_public:
                candidate_pools.append(fallback_pool)

        if not candidate_pools:
             return False

        # Scan used IPs once
        try:
            used = self._used_ips()
        except Exception as e:
            print(f"Warning: Failed to fetch used IPs for check: {e}")
            return True # Assume true on error to allow retry logic downstream, or False to be safe? 
                        # Better to fail open here and let the task handle the error, 
                        # but user wants to block if full. Let's return False if we really can't check?
                        # Actually, if PVE API fails, creation will fail anyway. 
            return False

        for pool in candidate_pools:
            try:
                s_obj = ipaddress.IPv4Address(pool["start_ip"])
                e_obj = ipaddress.IPv4Address(pool["end_ip"])
                gateway = pool.get("gateway")
                
                curr = int(s_obj)
                limit = int(e_obj)
                
                while curr <= limit:
                    ip_str = str(ipaddress.IPv4Address(curr))
                    # Quick check: is it known used?
                    if ip_str not in used and ip_str != gateway:
                        # If ping sweep is enabled, we technically should check it, 
                        # but doing a synchronous ping sweep in API is too slow.
                        # We accept that there's a race condition where PVE used check passes 
                        # but ping fails in the worker. 
                        # However, this method is primarily to catch "Pool is 100% full" scenario.
                        return True
                    curr += 1
            except ValueError:
                continue
        
        return False
