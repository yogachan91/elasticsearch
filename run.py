# run.py
import os
import uvicorn
from main import app  # ganti sesuai path ke FastAPI app-mu

if __name__ == "__main__":
    host = os.environ.get("APP_HOST", "0.0.0.0")
    port = int(os.environ.get("APP_PORT", "8000"))
    # workers=1 karena binary sendiri sudah menjalankan process
    uvicorn.run(app, host=host, port=port, log_level="info")
