from fastapi import APIRouter
from fastapi import WebSocket, WebSocketDisconnect
from pydantic import BaseModel
from typing import List, Optional
from ..elastic_client import es
from ..services import (
    get_suricata_events,
    get_sophos_events,
    get_panw_events,
    build_dynamic_filters,
    calculate_risk_summary,
    calculate_global_stats,
    build_event_type_stats,
    calculate_mitre_stats,
    calculate_global_attack
)
import requests
import os
import traceback
import asyncio
import json
import jwt
import httpx

INDEX = os.getenv("ELASTIC_INDEX")
INDEX_PANW = ".ds-logs-panw.panos-default-*"
INDEX_SEARCH = "logs-*"

router = APIRouter(prefix="/api/threats", tags=["Threat Analytics"])

# URL backend utama untuk verifikasi token
BACKEND_AUTH_VERIFY = os.getenv("AUTH_VERIFY_URL", "http://103.150.227.205:8080/api/auth/verify-token")

# ======================================================
# MODEL INPUT REQUEST
# ======================================================
class FilterItem(BaseModel):
    field: str
    operator: str
    value: str
class EventRequest(BaseModel):
    timeframe: str 
    filters: Optional[List[FilterItem]] = []
    search_query: Optional[str] = None

# @router.get("/counts")
# def threat_counts(timeframe: str = Query("yesterday")):
#     return get_threat_counts(timeframe)
#def threat_counts(timeframe: str = Query("yesterday"), db: Session = Depends(get_db)):
#    data = get_threat_counts(timeframe)

    # Cek jika data kosong
    # if not data:
    #     return {"message": "Data belum tersedia, tidak bisa di-record ke database."}
    
    # save_to_db(data, db)
    # return {"message": f"{len(data)} records berhasil disimpan ke DB", "data": data}



# ✅ Tambahan baru: ambil data dari PostgreSQL
# @router.get("/from-db")
# def get_threats_from_db(db: Session = Depends(get_db)):
#     data = db.query(CountIP).order_by(CountIP.created_date.desc()).limit(100).all()
#     return data

# ======================
# ENDPOINT TRANSFER KE SUPABASE USER LAIN
# ======================

# SUPABASE_TARGET_URL = os.getenv("SUPABASE_TARGET_URL")
# SUPABASE_TARGET_KEY = os.getenv("SUPABASE_TARGET_KEY")
# TARGET_TABLE = "countip"

# HEADERS = {
#     "apikey": SUPABASE_TARGET_KEY,
#     "Authorization": f"Bearer {SUPABASE_TARGET_KEY}",
#     "Content-Type": "application/json",
#     "Prefer": "return=representation"
# }

# @router.get("/transfer-countip")
# def transfer_countip(db: Session = Depends(get_db)):
    # 1) Ambil semua data dari lokal
    # local_rows = db.query(CountIP).all()
    # if not local_rows:
    #     return {"status": "no data found"}

    # 2) Siapkan payload JSON
    # payload = []
    # for row in local_rows:
    #     payload.append({
    #         "id": row.id,
    #         "rule_name": row.rule_name,
    #         "source_ip": row.source_ip,
    #         "destination_ip": row.destination_ip,
    #         "destination_geo_country": row.destination_geo_country,
    #         "event_severity_label": row.event_severity_label,
    #         "destination_port": row.destination_port,
    #         "counts": row.counts,
    #         "created_date": row.created_date.isoformat() if row.created_date else None,
    #         "first_seen_event": row.first_seen_event.isoformat() if row.first_seen_event else None,
    #         "last_seen_event": row.last_seen_event.isoformat() if row.last_seen_event else None,
    #         "modul": row.modul,
    #         "sub_type": row.sub_type
    #     })

    # 3) Kirim ke Supabase temanmu
    # rest_url = f"{SUPABASE_TARGET_URL}/rest/v1/{TARGET_TABLE}"
    # resp = requests.post(rest_url, json=payload, headers=HEADERS)

    # if resp.status_code in [200, 201]:
    #     return {"status": "success", "inserted": len(local_rows)}
    # else:
    #     return {"status": "failed", "code": resp.status_code, "detail": resp.text}
    

@router.post("/events/filter")
def get_filtered_events(body: EventRequest):

    timeframe = body.timeframe
    user_filters = build_dynamic_filters(body.filters)
    search_query = body.search_query.lower() if body.search_query else None

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

        elif f.operator == "is not":
            combined = [x for x in combined if str(x.get(field)) != value]

        elif f.operator == "exists":
            combined = [x for x in combined if str(x.get(field)) is not None]

        elif f.operator == "contains":
            combined = [x for x in combined if value.lower() in str(x.get(field, "")).lower()]

        elif f.operator == "starts_with":
            combined = [x for x in combined if str(x.get(field, "")).startswith(value)]

        elif f.operator == ">":
            try:
                filter_value = float(value)
                combined = [x for x in combined if float(x.get(field, "")) > filter_value]
            except (ValueError, TypeError):
                pass
        
        elif f.operator == "<":
            try:
                filter_value = float(value)
                combined = [x for x in combined if float(x.get(field, "")) < filter_value]
            except (ValueError, TypeError):
                pass

        
        # ----------------------------------------------------
    # 🆕 PEMBARUAN KRITIS: TERAPKAN LOGIKA SEARCH BAR (Universal Search)
    # ----------------------------------------------------
    
    if search_query:
        # Tentukan field mana yang akan dicari (Universal Search)
        # Tambahkan field lain jika diperlukan (misalnya 'port', 'protocol', 'application')
        searchable_fields = [
            "source_ip", 
            "destination_ip", 
            "country",        # Asumsi ini adalah source_country
            "event_type",
            "description",
            "severity",
            "mitre_stages"
        ]

        # Saring combined list: hanya simpan event yang cocok di SETIDAKNYA SATU field
        combined = [
            event for event in combined 
            if any(
                # Cek apakah search_query ada di field tersebut (case-insensitive)
                search_query in str(event.get(field, "")).lower()
                for field in searchable_fields
            )
        ]

    # Urutkan berdasarkan waktu
    combined_sorted = sorted(
        combined,
        key=lambda x: x.get("timestamp", ""),
        reverse=True
    )

    return {
        "timeframe": timeframe,
        "filters_applied": body.filters,
        "search_query_applied": body.search_query, # Opsional: untuk debugging
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
        global_attack = calculate_global_attack(combined)

        return {
            "timeframe": timeframe,
            "count": len(summary),
            "summary": summary,
            "mitre": mitre_stats,
            "global_attack": global_attack,
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
        
        
# ============================================================
# 🔐 HELPER: Verify Token ke Backend Utama
# ============================================================
async def verify_jwt_to_main_backend(token: str):
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            resp = await client.post(
                BACKEND_AUTH_VERIFY,
                json={"token": token}
            )
            resp.raise_for_status()
            return resp.json()
        except Exception:
            return {"valid": False}


# ============================================================
# 🔌 WEBSOCKET DENGAN SECURITY
# ============================================================
@router.websocket("/events/summary/ws")
async def summary_websocket(ws: WebSocket):
    # Accept WebSocket connection
    await ws.accept()

    # ============================================
    # 🔐 Validate JWT from query parameters
    # ============================================
    # token = ws.query_params.get("token")
    # if not token:
    #     await ws.close(code=4001)
    #     return

    # validation = await verify_jwt_to_main_backend(token)

    # if not validation.get("valid"):
    #     await ws.send_text(json.dumps({"error": "Invalid or expired token"}))
    #     await ws.close(code=4002)
    #     return

    # If valid → get user_id
    # user_id = validation.get("user_id")

    # print(f"WebSocket Connected by user_id={user_id}")

    # ============================================
    # 🔄 Main realtime loop
    # ============================================
    try:
        while True:
            # Terima request body dari frontend
            message = await ws.receive_text()
            body = json.loads(message)

            timeframe = body.get("timeframe", "last30days")
            filters = body.get("filters", [])

            # Ambil data dari Elasticsearch
            suricata = get_suricata_events(es, INDEX, timeframe) or []
            sophos = get_sophos_events(es, INDEX, timeframe) or []
            panw = get_panw_events(es, INDEX_PANW, timeframe) or []

            combined = suricata + sophos + panw

            # Build summary
            summary = calculate_risk_summary(combined)
            global_stats = calculate_global_stats(combined, timeframe)
            event_type_stats = build_event_type_stats(suricata, sophos, panw, timeframe)
            mitre_stats = calculate_mitre_stats(combined)

            response = {
                "timeframe": timeframe,
                "summary": summary,
                "global_stats": global_stats,
                "event_type_stats": event_type_stats,
                "mitre_stats": mitre_stats,
                "count": len(summary)
            }

            # Kirim hasil ke frontend (real-time)
            await ws.send_text(json.dumps(response))

            # Jika ingin ada delay supaya tidak spam
            await asyncio.sleep(0.5)

    except WebSocketDisconnect:
        print("Client disconnected")
    except Exception as e:
        print("WebSocket Error:", e)
        try:
            await ws.send_text(json.dumps({"error": str(e)}))
        except:
            pass
        await ws.close()



