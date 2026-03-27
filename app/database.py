from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

# SQLite database file — stored in project root
SQLALCHEMY_DATABASE_URL = "sqlite:///./vigilant.db"

# Create engine — connect_args needed for SQLite only
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)

# Session factory
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for all models
Base = declarative_base()


def get_db():
    """
    FastAPI dependency — yields a database session.
    Always closes the session after the request finishes.
    Use as: db: Session = Depends(get_db)
    """
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
def create_tables():
    """Create all database tables if they don't exist."""
    from app.models import db_models  # noqa: F401 — import triggers model registration
    Base.metadata.create_all(bind=engine)