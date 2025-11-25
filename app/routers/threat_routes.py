from fastapi import APIRouter, Query, Depends
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List
from ..elastic_client import es
from ..database import get_db
from ..models import CountIP, EventRequest
from ..services import (
    get_threat_counts,
    save_to_db,
    get_field_list,
    search_elastic,
    SearchRequest,
    get_suricata_events,
    get_sophos_events,
    get_panw_events,
    build_dynamic_filters,
    calculate_risk_summary,
    calculate_global_stats,
    build_event_type_stats,
    calculate_mitre_stats
)
import requests
import os
import traceback

INDEX = os.getenv("ELASTIC_INDEX")
INDEX_PANW = ".ds-logs-panw.panos-default-*"
INDEX_SEARCH = "logs-*"

router = APIRouter(prefix="/api/threats", tags=["Threat Analytics"])

# ======================================================
# MODEL INPUT REQUEST
# ======================================================
class FilterItem(BaseModel):
    field: str
    operator: str
    value: str


@router.get("/counts")
# def threat_counts(timeframe: str = Query("yesterday")):
#     return get_threat_counts(timeframe)
def threat_counts(timeframe: str = Query("yesterday"), db: Session = Depends(get_db)):
    data = get_threat_counts(timeframe)

    # Cek jika data kosong
    if not data:
        return {"message": "Data belum tersedia, tidak bisa di-record ke database."}
    
    # save_to_db(data, db)
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
            "sub_type": row.sub_type
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
    

    # ==============================================
# 🔍 SEARCH ENDPOINT (destination.ip / source.ip)
# ==============================================
# ======================================================
# GET ALL FIELDS (Mirip Kibana Discover)
# ======================================================
@router.get("/fields")
async def api_fields():
    fields = get_field_list()
    return {"fields": fields}


# ======================================================
# SEARCH DATA
# ======================================================
@router.post("/search")
async def api_search(request: SearchRequest):
    result = search_elastic(request.filters, request.timeframe)
    return result
    

@router.get("/events/filter")
def get_filtered_events(body: EventRequest):

    timeframe = body.timeframe
    user_filters = build_dynamic_filters(body.filters)

    suricata = get_suricata_events(es, INDEX, timeframe)
    sophos = get_sophos_events(es, INDEX, timeframe)
    panw = get_panw_events(es, INDEX_PANW, timeframe)

    # gabungkan semua data
    combined = suricata + sophos + panw

    # Apply filter manual di Python (post-filter)
    for f in body.filters:
        field = f.field
        value = f.value

        if f.operator == "is":
            combined = [x for x in combined if str(x.get(field)) == value]

        elif f.operator == "contains":
            combined = [x for x in combined if value.lower() in str(x.get(field, "")).lower()]

        elif f.operator == "starts_with":
            combined = [x for x in combined if str(x.get(field, "")).startswith(value)]

    # Urutkan berdasarkan waktu
    combined_sorted = sorted(
        combined,
        key=lambda x: x.get("timestamp", ""),
        reverse=True
    )

    return {
        "timeframe": timeframe,
        "filters_applied": body.filters,
        "count": len(combined_sorted),
        "events": combined_sorted
    }

@router.post("/events/summary")
def get_risk_summary(body: EventRequest):
    try:
        timeframe = body.timeframe

        suricata = get_suricata_events(es, INDEX, timeframe) or []
        sophos = get_sophos_events(es, INDEX, timeframe) or []
        panw = get_panw_events(es, INDEX_PANW, timeframe) or []

        combined = suricata + sophos + panw

        summary = calculate_risk_summary(combined)
        global_stats = calculate_global_stats(combined, timeframe)
        event_type_stats = build_event_type_stats(suricata, sophos, panw, timeframe)

        # 🔥 HITUNG MITRE
        mitre_stats = calculate_mitre_stats(combined)

        return {
            "timeframe": timeframe,
            "count": len(summary),
            "summary": summary,
            "mitre": mitre_stats,
            "events": [
                {
                    "total": global_stats["total"],
                    "seconds": global_stats["seconds"],
                    "list": event_type_stats
                }
            ]
        }

    except Exception as e:
        print("🔥 ERROR:", e)
        print(traceback.format_exc())
        raise







