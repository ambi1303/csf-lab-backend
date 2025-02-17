from database import engine
from models import Base

# Create all tables (if they don't exist)
Base.metadata.create_all(bind=engine)

print("Tables created successfully!")
