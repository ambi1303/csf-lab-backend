import asyncio
from database import SessionLocal
from models import Vulnerability

async def test_db():
    async with SessionLocal() as session:
        result = await session.execute("SELECT * FROM vulnerabilities")
        vulnerabilities = result.fetchall()
        print("Database Test Result:", vulnerabilities)

asyncio.run(test_db())
