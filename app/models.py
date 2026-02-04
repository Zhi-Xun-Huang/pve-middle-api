from sqlalchemy import Column, Integer, String, DateTime, Boolean, func
from .database import Base

class UserVM(Base):
    __tablename__ = "user_vms"

    id = Column(Integer, primary_key=True, index=True)
    vmid = Column(Integer, unique=True, index=True, nullable=False)
    vm_name = Column(String(255), index=True)
    vm_username = Column(String(255), default="ubuntu1") # Actual login user for the VM
    username = Column(String(255), index=True, nullable=False) # Creator's username
    user_role = Column(String(50), nullable=True)
    status = Column(String(50), default="unknown")
    ip_address = Column(String(50), nullable=True)
    cpu_cores = Column(Integer, nullable=True)
    memory_mb = Column(Integer, nullable=True)
    storage_gb = Column(Integer, nullable=True)
    gpu_count = Column(Integer, default=0)
    ib_count = Column(Integer, default=0)
    use_public_ip = Column(Integer, default=0) # 0=False, 1=True
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


class UserQuota(Base):
    __tablename__ = "user_quotas"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(255), unique=True, index=True, nullable=False)
    gpu_limit = Column(Integer, default=0)
    is_reseller = Column(Boolean, default=False)
    managed_by = Column(String(255), nullable=True, index=True) # Username of the reseller
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


class SystemConfig(Base):
    __tablename__ = "system_configs"

    key = Column(String(50), primary_key=True, index=True)
    value = Column(String(255), nullable=True) # JSON string or simple value
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime(timezone=True), onupdate=func.now(), server_default=func.now())


class IPPool(Base):
    __tablename__ = "ip_pools"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(50), nullable=True)
    type = Column(String(20), nullable=False) # 'private' or 'public'
    start_ip = Column(String(50), nullable=False)
    end_ip = Column(String(50), nullable=False)
    gateway = Column(String(50), nullable=True)
    cidr = Column(String(10), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
