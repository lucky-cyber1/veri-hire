from fastapi import FastAPI, Request, UploadFile, File
from fastapi.responses import HTMLResponse
import httpx

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
async def get_home():
    with open("app/templates/index.html", "r") as f:
        return HTMLResponse(content=f.read())

@app.post("/api/email-verify")
async def email_verify(file: UploadFile = File(...)):
    api_key = "vh_live_9f83b2a7e41c6d590218a4d70"
    # Proxy to the main VeriHire verification endpoint (adjust URL if needed)
    url = "http://127.0.0.1:8000/api/partner-verify"
    async with httpx.AsyncClient() as client:
        response = await client.post(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            files={"file": (file.filename, await file.read(), file.content_type)},
        )
        return response.json()
