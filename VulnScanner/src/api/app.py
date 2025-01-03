from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
import uvicorn
from ..core.scanner import VulnScanner
from ..database.db_manager import DatabaseManager

app = FastAPI(title="VulnScanner API")
scanner = VulnScanner()
db = DatabaseManager()

class ScanRequest(BaseModel):
    target: str
    ports: Optional[str] = "1-1000"
    web_scan: Optional[bool] = False

@app.post("/scan")
async def start_scan(scan_req: ScanRequest):
    try:
        results = {}
        results["port_scan"] = scanner.scan_ports(scan_req.target, scan_req.ports)
        
        if scan_req.web_scan:
            results["web_scan"] = scanner.scan_web_vulns(scan_req.target)
        
        # Sauvegarde en DB
        db.save_scan(scan_req.target, "full_scan", results)
        return results
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/history")
async def get_history():
    return {"scans": db.get_scan_history()}

def start_api():
    uvicorn.run(app, host="0.0.0.0", port=8000) 