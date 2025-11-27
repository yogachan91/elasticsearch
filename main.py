from fastapi import FastAPI
from app.routers import threat_routes
# from app.database import init_db
from dotenv import load_dotenv

# Load .env untuk Supabase key
load_dotenv()

# Inisialisasi DB (buat tabel jika belum ada)
# init_db()

app = FastAPI(title="Threat Analytics API")
app.include_router(threat_routes.router)

@app.get("/")
def read_root():
    return {"message": "Threat Analytics API is running 🚀"}
