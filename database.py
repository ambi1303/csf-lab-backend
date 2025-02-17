from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Database Configuration (Update with Neon Postgres credentials)
DATABASE_URL = "postgresql+asyncpg://neondb_owner:npg_3qB6RDACeKkJ@ep-black-credit-a8d7lhrf-pooler.eastus2.azure.neon.tech/neondb"

# Create Async Engine
engine = create_async_engine(
    DATABASE_URL,
    echo=True,
    connect_args={"ssl": True}  # Ensure SSL connection for Neon Postgres
)

# Create Async Session Factory
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    class_=AsyncSession
)

# Base Model for SQLAlchemy ORM
Base = declarative_base()
