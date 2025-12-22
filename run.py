import os
import uvicorn
# Pastikan path import benar sesuai struktur folder Anda
from main import app 

if __name__ == "__main__":
    # Mengambil port dari environment variable (default 8080 untuk Backend Utama)
    host = os.getenv("APP_HOST", "0.0.0.0")
    port = int(os.getenv("APP_PORT", "8000")) 
    
    print(f"Starting binary server on {host}:{port}")
    uvicorn.run(app, host=host, port=port, log_level="info")