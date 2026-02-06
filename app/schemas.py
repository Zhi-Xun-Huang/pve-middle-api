from typing import List, Optional

from pydantic import BaseModel, Field, validator


class VMCreateRequest(BaseModel):
    vmid: Optional[int] = Field(None, ge=100, description="Optional VMID, defaults to nextid() if omitted")
    vm_name: str = Field(..., description="Name for the new VM")
    username: str = Field(..., description="Cloud-init user")
    password: str = Field(..., description="Cloud-init password")
    storage_size: int = Field(..., gt=0, description="Root disk size in GiB")
    vm_profile: int = Field(..., ge=1, le=4, description="1=basic, 2=standard, 3=premium, 4=ultra")
    vm_template: int = Field(..., ge=1, description="Template VMID to clone (e.g. 1000, 2000)")
    required_ib: bool = Field(False, description="Whether the VM needs a matching IB device with each GPU")
    use_public_ip: bool = Field(False, description="Whether to assign a Public IP (external) or Private IP (internal)")
    ssh_public_key: Optional[str] = Field(None, description="Optional SSH public key (must be id_ed25519)")
    node: Optional[str] = Field(None, description="Override target node for creation (optional)")
    # Auditing / Identity fields
    creator_username: Optional[str] = Field(None, description="Username of the user creating the VM")
    creator_role: Optional[str] = Field(None, description="Role of the user creating the VM")
    creator_ip: Optional[str] = Field(None, description="IP address of the creator")

    @validator("ssh_public_key")
    def validate_ssh_key(cls, v: Optional[str]) -> Optional[str]:
        if v and not v.strip().startswith("ssh-ed25519"):
            raise ValueError("SSH public key must be of type ssh-ed25519")
        return v


class SystemConfigItem(BaseModel):
    key: str
    value: str
    description: Optional[str] = None

class SystemConfigUpdate(BaseModel):
    configs: List[SystemConfigItem]


class IPPoolCreate(BaseModel):
    name: Optional[str] = None
    type: str = Field(..., regex="^(private|public)$")
    start_ip: str
    end_ip: str
    gateway: Optional[str] = None
    cidr: Optional[str] = "24"

class IPPoolUpdate(BaseModel):
    name: Optional[str] = None
    type: Optional[str] = Field(None, regex="^(private|public)$")
    start_ip: Optional[str] = None
    end_ip: Optional[str] = None
    gateway: Optional[str] = None
    cidr: Optional[str] = None

class IPPoolResponse(IPPoolCreate):
    id: int

    class Config:
        orm_mode = True


class VMActionResponse(BaseModel):
    message: str
    task_id: Optional[str] = None
    raw: Optional[dict] = None


class VMCreateResponse(BaseModel):
    message: str
    vmid: int
    node: str
    ip: str
    public_ip: Optional[str] = None
    tasks: dict
    raw: Optional[dict] = None


class VMStatusResponse(BaseModel):
    vmid: int
    name: Optional[str] = None
    status: str
    qmpstatus: Optional[str] = None
    public_ip: Optional[str] = None
    info: dict


class VMSummary(BaseModel):
    vmid: int
    name: Optional[str] = None
    node: str
    status: str = "unknown"
    storage_size_gb: Optional[float] = None
    ip: Optional[str] = None
    public_ip: Optional[str] = None
    cpu_cores: Optional[int] = None
    memory_mb: Optional[int] = None
    vm_username: Optional[str] = None
    gpu_count: int = 0
    ib_count: int = 0
    vm_profile: Optional[int] = None
    required_ib: bool = False


class QuotaUpdateRequest(BaseModel):
    username: str = Field(..., description="Target username to update quota for")
    gpu_limit: int = Field(..., ge=0, description="New GPU limit")


class QuotaUpdateResponse(BaseModel):
    message: str
    username: str
    gpu_limit: int


class AssignResellerRequest(BaseModel):
    username: str
    reseller_username: Optional[str] = None # If None, remove from reseller (direct management)


class PromoteResellerRequest(BaseModel):
    username: str
    is_reseller: bool


class UserUsage(BaseModel):
    username: str
    role: str = "user"
    gpu_limit: int
    gpu_used: int
    vm_count: int
    reseller_code: Optional[str] = None


class VMMetricPoint(BaseModel):
    time: int
    cpu: Optional[float] = None
    mem: Optional[float] = None
    maxmem: Optional[float] = None
    netin: Optional[float] = None
    netout: Optional[float] = None
    diskread: Optional[float] = None
    diskwrite: Optional[float] = None


class VMMetricsResponse(BaseModel):
    vmid: int
    timeframe: str
    data: List[VMMetricPoint]


class FirewallRule(BaseModel):
    pos: Optional[int] = None
    enable: int = 1
    type: str  # 'in' or 'out'
    action: str # 'ACCEPT', 'DROP', 'REJECT'
    proto: Optional[str] = None
    dport: Optional[str] = None
    sport: Optional[str] = None
    source: Optional[str] = None
    dest: Optional[str] = None
    comment: Optional[str] = None
    log: Optional[str] = "nolog"


class FirewallResponse(BaseModel):
    vmid: int
    rules: List[FirewallRule]


class FirewallReorderRequest(BaseModel):
    old_pos: int
    new_pos: int
