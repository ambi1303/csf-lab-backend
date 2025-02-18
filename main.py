from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
import requests
import time
import logging
from pydantic import BaseModel
from typing import List
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy import Column, Integer, String, Text, Float
from sqlalchemy.future import select

logging.basicConfig(level=logging.INFO)

app = FastAPI()

# --------------------- OWASP ZAP Configuration ---------------------
ZAP_API_KEY = "48cskejggcig3thtlqhm8lm4sm"
ZAP_BASE_URL = "https://9dbf-103-169-236-163.ngrok-free.app"

# --------------------- Database Configuration (Neon Postgres) ---------------------
DATABASE_URL = "postgresql+asyncpg://neondb_owner:npg_3qB6RDACeKkJ@ep-black-credit-a8d7lhrf-pooler.eastus2.azure.neon.tech/neondb"
engine = create_async_engine(DATABASE_URL, echo=True, connect_args={"ssl": True})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine, class_=AsyncSession)
Base = declarative_base()

# --------------------- Database Model ---------------------
class Vulnerability(Base):
    __tablename__ = "vulnerabilities"
    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, index=True)
    description = Column(Text)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True)
    references = Column(Text, nullable=True)

# --------------------- Database Initialization ---------------------
async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

@app.on_event("startup")
async def startup_event():
    await init_db()

# --------------------- Dependency for Database Session ---------------------
async def get_db():
    async with SessionLocal() as session:
        yield session

# --------------------- OWASP ZAP Helper Functions ---------------------
def check_zap_connection():
    """Check if OWASP ZAP is accessible."""
    try:
        response = requests.get(f"{ZAP_BASE_URL}/JSON/core/view/version/", params={"apikey": ZAP_API_KEY}, timeout=5)
        return response.status_code == 200
    except requests.RequestException:
        return False

def wait_for_spider_completion(spider_id: str, timeout: int = 60):
    """Wait for ZAP spider scan to complete."""
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            response = requests.get(f"{ZAP_BASE_URL}/JSON/spider/view/status/", 
                                    params={"apikey": ZAP_API_KEY, "scanId": spider_id}, 
                                    timeout=5).json()
            if int(response.get('status', 0)) >= 100:
                return True
            time.sleep(2)
        except requests.RequestException:
            return False
    return False

# --------------------- Request Models ---------------------
class ScanRequest(BaseModel):
    target_url: str

# --------------------- API Endpoints ---------------------

@app.post("/scan/start")
async def start_scan(scan_request: ScanRequest):
    """Start a ZAP scan."""
    target_url = scan_request.target_url
    logging.info(f"Received scan request for {target_url}")

    if not check_zap_connection():
        logging.error("ZAP is not accessible")
        raise HTTPException(status_code=503, detail="ZAP is not accessible")

    try:
        logging.info("Starting ZAP spider scan...")
        spider_response = requests.get(f"{ZAP_BASE_URL}/JSON/spider/action/scan/", 
                                       params={"apikey": ZAP_API_KEY, "url": target_url}, 
                                       timeout=10).json()
        logging.info(f"ZAP Spider response: {spider_response}")

        if "scan" not in spider_response:
            logging.error("Failed to start spider scan")
            raise HTTPException(status_code=500, detail="Failed to start spider scan")

        spider_id = spider_response['scan']
        wait_for_spider_completion(spider_id)
        logging.info(f"Spider scan {spider_id} completed.")

        return {"message": "Scan started successfully", "scan_id": spider_id, "target_url": target_url}
    except requests.RequestException as e:
        logging.error(f"Request Exception: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan/{scan_id}/report/json")
async def get_scan_report_json(scan_id: str, target_url: str):
    """Retrieve scan report in JSON format."""
    if not check_zap_connection():
        raise HTTPException(status_code=503, detail="ZAP is not accessible")
    
    response = requests.get(f"{ZAP_BASE_URL}/JSON/alert/view/alerts/", 
                            params={"apikey": ZAP_API_KEY, "baseurl": target_url}, 
                            timeout=5).json()
    return {"scan_id": scan_id, "alerts": response.get('alerts', [])}

@app.get("/scan/list")
async def list_scans(db: AsyncSession = Depends(get_db)):
    """List all stored scans from the database."""
    result = await db.execute(select(Vulnerability))
    scans = result.scalars().all()
    return {"scans": [scan.__dict__ for scan in scans]}

@app.post("/fetch_nvd")
async def trigger_fetch_nvd(background_tasks: BackgroundTasks):
    """Trigger background task to fetch NVD data."""
    background_tasks.add_task(fetch_nvd_data)
    return {"message": "Fetching NVD data in the background"}

async def fetch_nvd_data():
    """Fetch latest NVD data and store in the database."""
    url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
    except requests.RequestException as e:
        logging.error(f"Error fetching NVD data: {e}")
        return

    vulnerabilities = []
    for cve_item in data.get("result", {}).get("CVE_Items", []):
        cve_id = cve_item["cve"]["CVE_data_meta"]["ID"]
        description = cve_item["cve"]["description"]["description_data"][0]["value"]
        cvss_score = cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseScore", None)
        severity = cve_item.get("impact", {}).get("baseMetricV3", {}).get("cvssV3", {}).get("baseSeverity", None)
        references = ", ".join(ref["url"] for ref in cve_item["cve"]["references"]["reference_data"])
        vulnerabilities.append({"cve_id": cve_id, "description": description, "cvss_score": cvss_score, "severity": severity, "references": references})

    async with SessionLocal() as session:
        async with session.begin():
            for vuln in vulnerabilities:
                session.add(Vulnerability(**vuln))
        await session.commit()

    logging.info("NVD Data Fetched and Stored Successfully")

# --------------------- Run FastAPI Application ---------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8090)
