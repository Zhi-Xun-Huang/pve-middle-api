from sqlalchemy import text
from app.database import engine

def migrate():
    with engine.connect() as conn:
        try:
            conn.execute(text("ALTER TABLE user_quotas ADD COLUMN is_reseller BOOLEAN DEFAULT 0"))
            print("Added is_reseller column")
        except Exception as e:
            print(f"Skipped is_reseller: {e}")
            
        try:
            conn.execute(text("ALTER TABLE user_quotas ADD COLUMN managed_by VARCHAR(255)"))
            print("Added managed_by column")
        except Exception as e:
            print(f"Skipped managed_by: {e}")
            
        try:
            conn.execute(text("CREATE INDEX ix_user_quotas_managed_by ON user_quotas (managed_by)"))
            print("Added index for managed_by")
        except Exception as e:
            print(f"Skipped index: {e}")

if __name__ == "__main__":
    migrate()
