from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, declarative_base

from .config import get_settings

settings = get_settings()

# Check if we are using SQLite
connect_args = {}
if settings.database_url.startswith("sqlite"):
    connect_args = {"check_same_thread": False}

engine = create_engine(
    settings.database_url, 
    connect_args=connect_args,
    pool_recycle=3600,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Auth Database Setup
engine_auth = None
SessionAuth = None

if settings.auth_database_url:
    connect_args_auth = {}
    if settings.auth_database_url.startswith("sqlite"):
        connect_args_auth = {"check_same_thread": False}
        
    engine_auth = create_engine(
        settings.auth_database_url,
        connect_args=connect_args_auth,
        pool_recycle=3600,
        pool_pre_ping=True
    )
    SessionAuth = sessionmaker(autocommit=False, autoflush=False, bind=engine_auth)

Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_auth_db():
    """
    Dependency to get session for the Auth database.
    Raises RuntimeError if AUTH_DATABASE_URL is not configured.
    """
    if SessionAuth is None:
        raise RuntimeError("Auth database is not configured in settings.")
    
    db = SessionAuth()
    try:
        yield db
    finally:
        db.close()
