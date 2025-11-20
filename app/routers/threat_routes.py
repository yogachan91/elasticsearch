from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from ..database import get_db
from ..models import CountIP
from ..services import (
    get_threat_counts,
    save_to_db,
)
import requests
import os

router = APIRouter(prefix="/api/threats", tags=["Threat Analytics"])

@router.get("/counts")
# def threat_counts(timeframe: str = Query("yesterday")):
#     return get_threat_counts(timeframe)
def threat_counts(timeframe: str = Query("yesterday"), db: Session = Depends(get_db)):
    data = get_threat_counts(timeframe)

    # Cek jika data kosong
    if not data:
        return {"message": "Data belum tersedia, tidak bisa di-record ke database."}
    
    save_to_db(data, db)
    return {"message": f"{len(data)} records berhasil disimpan ke DB", "data": data}



# ✅ Tambahan baru: ambil data dari PostgreSQL
@router.get("/from-db")
def get_threats_from_db(db: Session = Depends(get_db)):
    data = db.query(CountIP).order_by(CountIP.created_date.desc()).limit(100).all()
    return data

# ======================
# ENDPOINT TRANSFER KE SUPABASE USER LAIN
# ======================

SUPABASE_TARGET_URL = os.getenv("SUPABASE_TARGET_URL")
SUPABASE_TARGET_KEY = os.getenv("SUPABASE_TARGET_KEY")
TARGET_TABLE = "countip"

HEADERS = {
    "apikey": SUPABASE_TARGET_KEY,
    "Authorization": f"Bearer {SUPABASE_TARGET_KEY}",
    "Content-Type": "application/json",
    "Prefer": "return=representation"
}

@router.get("/transfer-countip")
def transfer_countip(db: Session = Depends(get_db)):
    # 1) Ambil semua data dari lokal
    local_rows = db.query(CountIP).all()
    if not local_rows:
        return {"status": "no data found"}

    # 2) Siapkan payload JSON
    payload = []
    for row in local_rows:
        payload.append({
            "id": row.id,
            "rule_name": row.rule_name,
            "source_ip": row.source_ip,
            "destination_ip": row.destination_ip,
            "destination_geo_country": row.destination_geo_country,
            "event_severity_label": row.event_severity_label,
            "destination_port": row.destination_port,
            "counts": row.counts,
            "created_date": row.created_date.isoformat() if row.created_date else None,
            "first_seen_event": row.first_seen_event.isoformat() if row.first_seen_event else None,
            "last_seen_event": row.last_seen_event.isoformat() if row.last_seen_event else None,
            "modul": row.modul,
            "sub_type": row.sub_type,
            "tipe": row.tipe
        })

    # 3) Kirim ke Supabase temanmu
    rest_url = f"{SUPABASE_TARGET_URL}/rest/v1/{TARGET_TABLE}"
    resp = requests.post(rest_url, json=payload, headers=HEADERS)

    if resp.status_code in [200, 201]:
        return {"status": "success", "inserted": len(local_rows)}
    else:
        return {"status": "failed", "code": resp.status_code, "detail": resp.text}
    

# ======================
# ENDPOINT MENGUBAH TYPE KOLOM DATABASE USER LAIN
# ======================

@router.get("/alter-column")
def alter_supabase_column():
    """
    Mengubah tipe kolom 'id' di tabel countip teman menjadi character varying (text)
    """
    rest_url = f"{SUPABASE_TARGET_URL}/rest/v1/rpc"
    sql_query = """
        ALTER TABLE public.countip 
        ALTER COLUMN id TYPE character varying 
        USING id::character varying;
    """

    # Supabase SQL API (gunakan endpoint PostgREST bawaan untuk RPC SQL)
    sql_headers = {
        "apikey": SUPABASE_TARGET_KEY,
        "Authorization": f"Bearer {SUPABASE_TARGET_KEY}",
        "Content-Type": "application/json"
    }

    # Mengirim query SQL lewat Supabase REST API bawaan
    payload = {
        "query": sql_query
    }

    response = requests.post(
        f"{SUPABASE_TARGET_URL}/rest/v1/rpc/sql",
        json=payload,
        headers=sql_headers
    )

    if response.status_code in [200, 201, 204]:
        return {"status": "success", "message": "Kolom 'id' berhasil diubah menjadi character varying"}
    else:
        return {
            "status": "failed",
            "code": response.status_code,
            "detail": response.text
        }

