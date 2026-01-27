from functools import lru_cache

from pydantic import BaseSettings, Field


class Settings(BaseSettings):
    proxmox_host: str = Field(..., env="PROXMOX_HOST")
    proxmox_port: int = Field(..., env="PROXMOX_PORT")
    proxmox_user: str = Field(..., env="PROXMOX_USER")
    proxmox_token_name: str = Field(..., env="PROXMOX_TOKEN_NAME")
    proxmox_token_value: str = Field(..., env="PROXMOX_TOKEN_VALUE")
    proxmox_verify_ssl: bool = Field(..., env="PROXMOX_VERIFY_SSL")
    proxmox_timeout: int = Field(..., env="PROXMOX_TIMEOUT")
    proxmox_node: str | None = Field(
        ...,
        env="PROXMOX_NODE",
        description="Default node used for VM creation; runtime operations auto-resolve by vmid",
    )
    storage_name: str = Field(..., env="PVE_STORAGE_NAME")
    ip_pool_cidr: str = Field(..., env="PVE_IP_POOL")
    ip_gateway: str = Field(..., env="PVE_IP_GATEWAY")
    ip_dns: str = Field(..., env="PVE_IP_DNS")
    ip_lock_file: str = Field(..., env="PVE_IP_LOCK_FILE")
    ip_ping_sweep: bool = Field(..., env="PVE_IP_PING_SWEEP")
    ip_ping_timeout_ms: int = Field(..., env="PVE_IP_PING_TIMEOUT_MS", ge=1)
    
    # Database Settings
    database_url: str = Field(..., env="DATABASE_URL")
    auth_database_url: str | None = Field(..., env="AUTH_DATABASE_URL")

    # Redis Settings
    redis_url: str = Field(..., env="REDIS_URL")

    # API Docs Security
    docs_username: str = Field(..., env="DOCS_USERNAME")
    docs_password: str = Field(..., env="DOCS_PASSWORD")

    # External Auth
    auth_api_url: str = Field(..., env="AUTH_API_URL")

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache()
def get_settings() -> Settings:
    return Settings()