from datetime import datetime, timedelta
from .elastic_client import es
# from .database import SessionLocal
# from .models import CountIP
# from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from collections import defaultdict
from datetime import datetime   
from dateutil import parser
import os
import math
import re

INDEX = os.getenv("ELASTIC_INDEX")
INDEX_PANW = ".ds-logs-panw.panos-default-*"
INDEX_SEARCH = "logs-*"

class FilterItem(BaseModel):
    field: str
    operator: str
    value: Optional[str] = None

class SearchRequest(BaseModel):
    filters: List[FilterItem] = []
    timeframe: Optional[str] = None


def get_time_range_filter(timeframe: str):
    now = datetime.utcnow()
    if timeframe == "today":
        # mulai dari jam 00:00 UTC
        start = datetime(now.year, now.month, now.day)
    elif timeframe == "yesterday":
        start = now - timedelta(days=1)
    elif timeframe == "8hours" or timeframe == "last8hours":
        start = now - timedelta(hours=8)
    elif timeframe == "24hours" or timeframe == "last24hours":
        start = now - timedelta(hours=24)
    elif timeframe == "last3days":
        start = now - timedelta(days=3)
    elif timeframe == "last7days":
        start = now - timedelta(days=7)
    elif timeframe == "last30days":
        start = now - timedelta(days=30)
    elif timeframe == "last60days":
        start = now - timedelta(days=60)
    elif timeframe == "last90days":
        start = now - timedelta(days=90)
    else:
        start = now - timedelta(days=1)
    return {"range": {"@timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}}

def get_time_range_for_stats(timeframe: str):
    now = datetime.utcnow()

    if timeframe == "today":
        start = datetime(now.year, now.month, now.day)
    elif timeframe == "yesterday":
        start = now - timedelta(days=1)
    elif timeframe in ["8hours", "last8hours"]:
        start = now - timedelta(hours=8)
    elif timeframe in ["24hours", "last24hours"]:
        start = now - timedelta(hours=24)
    elif timeframe == "last3days":
        start = now - timedelta(days=3)
    elif timeframe == "last7days":
        start = now - timedelta(days=7)
    elif timeframe == "last30days":
        start = now - timedelta(days=30)
    elif timeframe == "last60days":
        start = now - timedelta(days=60)
    elif timeframe == "last90days":
        start = now - timedelta(days=90)
    else:
        start = now - timedelta(days=1)

    return start, now

def get_suricata_events(es, INDEX, timeframe):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    get_time_range_filter(timeframe),
                    {"term": {"event.module": "suricata"}}
                ]
            }
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.name.keyword", "size": 500},
                "aggs": {
                    "sample_event": {
                        "top_hits": {
                            "size": 1,
                            "sort": [{"@timestamp": {"order": "desc"}}],
                            "_source": [
                                "source.ip",
                                "destination.ip",
                                "rule.category",
                                "source.geo.country_name",
                                "destination.geo.country_name",
                                "event.severity_label",
                                "destination.port",
                                "mitre.stages",
                                "log.id.uid",
                                "network.transport",
                                "source.geo.location.lon",
                                "source.geo.location.lat",
                                "destination.geo.location.lon",
                                "destination.geo.location.lat",
                                "@timestamp"
                            ]
                        }
                    },
                    "first_event": {"min": {"field": "@timestamp"}},
                    "last_event": {"max": {"field": "@timestamp"}}
                }
            }
        }
    }

    res = es.search(index=INDEX, body=query)

    results = []
    for bucket in res["aggregations"]["by_rule"]["buckets"]:
        hit = bucket["sample_event"]["hits"]["hits"][0]["_source"] if bucket["sample_event"]["hits"]["hits"] else {}

        results.append({
            "destination_ip": hit.get("destination", {}).get("ip"),
            "source_ip": hit.get("source", {}).get("ip"),
            "country": hit.get("source", {}).get("geo", {}).get("country_name"),
            "event_type": "suricata",
            "sub_type": hit.get("rule", {}).get("category"),
            "severity": hit.get("event", {}).get("severity_label"),
            "timestamp": hit.get("@timestamp"),
            "mitre_stages": hit.get("mitre", {}).get("stages"),
            "event_id": hit.get("log", {}).get("id", {}).get("uid"),
            "application": "application",
            "description": bucket["key"],
            "protocol": hit.get("network", {}).get("transport"),
            "destination_country": hit.get("destination", {}).get("geo", {}).get("country_name"),
            "port": hit.get("destination", {}).get("port"),
            "count": bucket["doc_count"],
            "first_event": bucket["first_event"].get("value_as_string"),
            "last_event": bucket["last_event"].get("value_as_string"),
            "source_longitude": hit.get("source", {}).get("geo", {}).get("location", {}).get("lon"),
            "source_latitude": hit.get("source", {}).get("geo", {}).get("location", {}).get("lat"),
            "destination_longitude": hit.get("destination", {}).get("geo", {}).get("location", {}).get("lon"),
            "destination_latitude": hit.get("destination", {}).get("geo", {}).get("location", {}).get("lat")
        })

    return results

def get_sophos_events(es, INDEX, timeframe):
    query = {
        "size": 500,
        "query": {
            "bool": {
                "filter": [
                    get_time_range_filter(timeframe),
                    {"term": {"event.module": "sophos"}},
                    {"terms": {"sophos.xg.log_type": ["IDP", "Content Filtering"]}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    res = es.search(index=INDEX, body=query)
    hits = res.get("hits", {}).get("hits", [])
    results = []

    for h in hits:
        src = h["_source"]
        sophos = src.get("sophos", {}).get("xg", {})

        rule_name = (
            sophos.get("message") or
            sophos.get("rule_name") or
            "unknown"
        )

        results.append({
            "destination_ip": src.get("destination", {}).get("ip"),
            "source_ip": src.get("source", {}).get("ip"),
            "country": src.get("source", {}).get("geo", {}).get("country_name")
                or src.get("destination", {}).get("geo", {}).get("country_name"),
            "event_type": "sophos",
            "sub_type": sophos.get("log_type"),
            "severity": src.get("event", {}).get("severity_label") or src.get("log", {}).get("level"),
            "timestamp": src.get("@timestamp"),
            "mitre_stages": src.get("mitre", {}).get("stages"),
            "event_id": src.get("log", {}).get("id", {}).get("uid"),
            "application": sophos.get("app_name"),
            "description": rule_name,
            "protocol": src.get("network", {}).get("transport"),
            "destination_country": src.get("destination", {}).get("geo", {}).get("country_name")
                or src.get("source", {}).get("geo", {}).get("country_name"),
            "port": src.get("destination", {}).get("port") or sophos.get("dst_port"),
            "count": 1,
            "first_event": src.get("@timestamp"),
            "last_event": src.get("@timestamp"),
            "source_longitude": src.get("source", {}).get("geo", {}).get("location", {}).get("lon"),
            "source_latitude": src.get("source", {}).get("geo", {}).get("location", {}).get("lat"),
            "destination_longitude": src.get("destination", {}).get("geo", {}).get("location", {}).get("lon"),
            "destination_latitude": src.get("destination", {}).get("geo", {}).get("location", {}).get("lat")
        })

    return results

def get_panw_events(es, INDEX_PANW, timeframe):
    query = {
        "size": 500,
        "query": {
            "bool": {
                "filter": [
                    get_time_range_filter(timeframe),
                    {"term": {"event.module": "panw"}},
                    {"term": {"panw.panos.type": "THREAT"}},
                    {"terms": {"panw.panos.sub_type": ["file", "vulnerability"]}}
                ]
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    res = es.search(index=INDEX_PANW, body=query)
    hits = res.get("hits", {}).get("hits", [])

    results = []

    for h in hits:
        src = h["_source"]
        panw = src.get("panw", {}).get("panos", {})

        results.append({
            "destination_ip": src.get("destination", {}).get("ip"),
            "source_ip": src.get("source", {}).get("ip"),
            "country": src.get("source", {}).get("geo", {}).get("country_name")
                or src.get("destination", {}).get("geo", {}).get("country_name"),
            "event_type": "panw",
            "sub_type": panw.get("sub_type"),
            "severity": src.get("log", {}).get("syslog", {}).get("severity", {}).get("name"),
            "timestamp": src.get("@timestamp"),
            "mitre_stages": src.get("mitre", {}).get("stages"),
            "event_id": panw.get("seqno"),
            "application": panw.get("app"),
            "description": panw.get("threat", {}).get("name"),
            "protocol": src.get("network", {}).get("transport"),
            "destination_country": src.get("destination", {}).get("geo", {}).get("country_name")
                or src.get("source", {}).get("geo", {}).get("country_name"),
            "port": src.get("destination", {}).get("port") or panw.get("dest_port"),
            "count": 1,
            "first_event": src.get("@timestamp"),
            "last_event": src.get("@timestamp"),
            "source_longitude": src.get("source", {}).get("geo", {}).get("location", {}).get("lon"),
            "source_latitude": src.get("source", {}).get("geo", {}).get("location", {}).get("lat"),
            "destination_longitude": src.get("destination", {}).get("geo", {}).get("location", {}).get("lon"),
            "destination_latitude": src.get("destination", {}).get("geo", {}).get("location", {}).get("lat")
        })

    return results

def compute_top5_risk(combined):

    # =============================
    # STEP 1: Build base table
    # =============================
    base = []
    for ev in combined:
        src = str(ev.get("source_ip", "")).split("/")[0]
        dst = str(ev.get("destination_ip", "")).split("/")[0]

        internal_ip = None
        if src.startswith("192.168."):
            internal_ip = src
        elif dst.startswith("192.168."):
            internal_ip = dst

        if not internal_ip:
            continue

        base.append({
            "created_date": datetime.utcnow(),
            "modul": ev.get("event_type", "").lower(),
            "severity": str(ev.get("event_severity_label", "")).lower(),
            "sub_type": str(ev.get("sub_type", "")).lower(),
            "rule_name": str(ev.get("description", "")),
            "internal_ip": internal_ip
        })

    if not base:
        return []

    # =============================
    # STEP 2: COUNT RULE PER IP
    # =============================
    rule_count = defaultdict(int)
    for b in base:
        key = (b["internal_ip"], b["rule_name"])
        rule_count[key] += 1

    # =============================
    # STEP 3: SCORE PER EVENT
    # =============================
    per_event_scores = []

    for b in base:
        ip = b["internal_ip"]
        rn = b["rule_name"]

        # modul weight
        m = b["modul"]
        if m == "suricata":
            w_modul = 1.0
        elif m == "panw":
            w_modul = 1.2
        elif m == "sophos":
            w_modul = 1.3
        else:
            w_modul = 1.0

        # severity weight
        sev = b["severity"]
        if sev in ("critical", "severe"):
            w_severity = 5.0
        elif sev == "high":
            w_severity = 3.5
        elif sev == "medium":
            w_severity = 2.0
        elif sev == "low":
            w_severity = 1.0
        else:
            w_severity = 0.5

        # subtype weight
        st = b["sub_type"]
        if st in ("malware", "c2", "command_and_control", "data_exfil", "exfiltration"):
            w_sub_type = 5.5
        elif st in ("exploit_attempt", "exploit", "intrusion", "lateral_movement"):
            w_sub_type = 4.5
        elif st in ("auth_bruteforce", "password_spray", "credential_access"):
            w_sub_type = 3.8
        elif st in ("policy_violation", "misconfiguration"):
            w_sub_type = 1.8
        else:
            w_sub_type = 1.0

        # rule weight
        rn_lower = rn.lower()
        if ("mimikatz" in rn_lower) or ("c2" in rn_lower) or ("ransomware" in rn_lower):
            w_rule = 1.4
        elif ("port scan" in rn_lower) or ("generic" in rn_lower):
            w_rule = 0.8
        else:
            w_rule = 1.0

        # decay
        time_decay = math.exp(-1)

        # duplicate dampening
        rc = rule_count[(ip, rn)]
        dup_damp = 1.0 / (1.0 + math.log(max(rc, 1)))

        # final event score
        event_score = (
            w_modul * w_severity * w_sub_type * w_rule *
            time_decay * dup_damp
        )

        per_event_scores.append({
            "internal_ip": ip,
            "modul": b["modul"],
            "sub_type": b["sub_type"],
            "event_score": event_score
        })

    # =============================
    # STEP 4: AGGREGATE per IP
    # =============================
    ip_data = defaultdict(lambda: {
        "event_count": 0,
        "modules": set(),
        "sub_types": set(),
        "raw_score": 0.0
    })

    for ev in per_event_scores:
        ip = ev["internal_ip"]
        ip_data[ip]["event_count"] += 1
        ip_data[ip]["modules"].add(ev["modul"])
        ip_data[ip]["sub_types"].add(ev["sub_type"])
        ip_data[ip]["raw_score"] += ev["event_score"]

    results = []

    # =============================
    # STEP 5: FINAL SCORE
    # =============================
    for ip, d in ip_data.items():
        modul_count = len(d["modules"])
        sub_type_count = len(d["sub_types"])

        score_raw = d["raw_score"]
        score_raw *= (1 + 0.2 * (modul_count - 1))
        score_raw *= (1 + 0.1 * min(sub_type_count - 1, 3))

        score_normalized = min(100, max(1, score_raw * 2))

        # severity level
        if score_normalized >= 80:
            sev_label = "Critical"
        elif score_normalized >= 60:
            sev_label = "High"
        elif score_normalized >= 30:
            sev_label = "Medium"
        else:
            sev_label = "Low"

        results.append({
            "ip": ip,
            "event_count": d["event_count"],
            "modul_count": modul_count,
            "sub_type_count": sub_type_count,
            "score": round(score_normalized, 2),
            "severity": sev_label
        })

    # urutkan DESC score
    results = sorted(results, key=lambda x: x["score"], reverse=True)

    return results[:5]

def calculate_risk_summary(events):

    # --- Step 1: Base Extract ---
    base = []

    for e in events:
        src_ip = e.get("source_ip")
        dst_ip = e.get("destination_ip")

        # ambil IP internal
        def extract_internal_ip(ip):
            if not ip:
                return None
            if ip.startswith("192.168."):
                return ip.split("/")[0]
            return None

        internal_ip = extract_internal_ip(src_ip) or extract_internal_ip(dst_ip)
        if not internal_ip:
            continue

        base.append({
            "internal_ip": internal_ip,
            "modul": e.get("event_type", "").lower(),
            "sub_type": (e.get("sub_type") or "").lower(),
            "severity": (e.get("severity") or "").lower(),
            "rule_name": e.get("description") or "",
        })

    if not base:
        return []

    # --- Step 2: Hitung rule count untuk dup_damp ---
    rule_count_map = {}
    for b in base:
        key = (b["internal_ip"], b["rule_name"])
        rule_count_map[key] = rule_count_map.get(key, 0) + 1

    # --- Step 3: Hitung score per event ---
    scored = []

    for b in base:
        # modul weight
        w_modul = {
            "suricata": 1.0,
            "panw": 1.2,
            "sophos": 1.3
        }.get(b["modul"], 1.0)

        # severity weight
        w_severity = {
            "critical": 5.0,
            "severe": 5.0,
            "high": 3.5,
            "medium": 2.0,
            "low": 1.0
        }.get(b["severity"], 0.5)

        # subtype weight
        sub = b["sub_type"]
        if sub in ["malware","c2","command_and_control","data_exfil","exfiltration"]:
            w_sub = 5.5
        elif sub in ["exploit_attempt","exploit","intrusion","lateral_movement"]:
            w_sub = 4.5
        elif sub in ["auth_bruteforce","password_spray","credential_access"]:
            w_sub = 3.8
        elif sub in ["policy_violation","misconfiguration"]:
            w_sub = 1.8
        else:
            w_sub = 1.0

        # rule weight
        rn = b["rule_name"].lower()
        if "mimikatz" in rn or "c2" in rn or "ransomware" in rn:
            w_rule = 1.4
        elif "port scan" in rn or "generic" in rn:
            w_rule = 0.8
        else:
            w_rule = 1.0

        # dup damping
        rc = rule_count_map[(b["internal_ip"], b["rule_name"])]
        dup_damp = 1.0 / (1.0 + math.log(max(rc, 1)))

        scored.append({
            "internal_ip": b["internal_ip"],
            "modul": b["modul"],
            "sub_type": b["sub_type"],
            "event_score": w_modul * w_severity * w_sub * w_rule * math.exp(-1) * dup_damp
        })

    # --- Step 4: Aggregate per IP ---
    ip_map = {}

    for s in scored:
        ip = s["internal_ip"]
        if ip not in ip_map:
            ip_map[ip] = {
                "event_count": 0,
                "modul_set": set(),
                "sub_type_set": set(),
                "raw_score": 0.0
            }

        ip_map[ip]["event_count"] += 1
        ip_map[ip]["modul_set"].add(s["modul"])
        ip_map[ip]["sub_type_set"].add(s["sub_type"])
        ip_map[ip]["raw_score"] += s["event_score"]

    results = []

    # --- Step 5: Calculate final score ---
    for ip, d in ip_map.items():

        modul_count = len(d["modul_set"])
        sub_type_count = len(d["sub_type_set"])

        raw = d["raw_score"]

        # koreksi modul & subtype
        raw *= (1 + 0.2 * (modul_count - 1))
        raw *= (1 + 0.1 * min(sub_type_count - 1, 3))

        # normalisasi 1 - 100
        score = max(1, min(100, raw * 2))

        # severity label
        if score >= 80:
            sev = "Critical"
        elif score >= 60:
            sev = "High"
        elif score >= 30:
            sev = "Medium"
        else:
            sev = "Low"

        results.append({
            "ip": ip,
            "event_count": d["event_count"],
            "modul_count": modul_count,
            "sub_type_count": sub_type_count,
            "score": round(score, 2),
            "severity": sev
        })

    # top 5
    return sorted(results, key=lambda x: x["score"], reverse=True)[:5]


def calculate_global_stats(events, timeframe):
    start, end = get_time_range_for_stats(timeframe)

    total = len(events)
    
    # ----------------------------------------------------
    # KODE PERUBAHAN UTAMA UNTUK PER_SECOND DIMULAI DI SINI
    # ----------------------------------------------------
    
    if timeframe == "today":
        # Jika timeframe adalah "today", bagi total dengan 900
        per_second = round(total / 900, 2)
    else:
        # Jika timeframe adalah selain "today", nilai per_second adalah 0
        per_second = 0 
        
    # ----------------------------------------------------
    # KODE PERUBAHAN UTAMA UNTUK PER_SECOND SELESAI DI SINI
    # ----------------------------------------------------

    return {
        "total": total,
        # Ubah key "seconds" menjadi sesuatu yang lebih deskriptif 
        # karena nilainya tidak lagi mewakili event/second yang sebenarnya.
        # Misalnya, kita tetap menggunakan "per_second"
        "seconds": per_second 
    }
    

def build_timeline(events, timeframe):
    timeline = defaultdict(int)

    for ev in events:
        ts = ev.get("timestamp")
        if ts is None:
            continue

        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))

        if timeframe in ["today", "8hours", "last8hours", "24hours", "last24hours"]:
            key = dt.strftime("%Y-%m-%d %H:00")   # tampilkan tanggal + jam
        else:
            # timeline per hari + jam (kalau mau jam juga ditampilkan)
            key = dt.strftime("%Y-%m-%d %H:00")

        timeline[key] += 1

    return [
        {"timeline": k, "count": v}
        for k, v in sorted(timeline.items())
    ]

def build_event_type_stats(suricata, sophos, panw, timeframe):
    return [
        {
            "event_type": "suricata",
            "total": len(suricata),
            "timeline": build_timeline(suricata, timeframe)
        },
        {
            "event_type": "sophos",
            "total": len(sophos),
            "timeline": build_timeline(sophos, timeframe)
        },
        {
            "event_type": "panw",
            "total": len(panw),
            "timeline": build_timeline(panw, timeframe)
        }
    ]

def calculate_global_attack(events):
    """
    Mengambil 5 event terbaru yang memiliki severity 'Notice' atau 'Informational'.
    """
    
    events_with_timestamp = []

    # 1. Filtering dan Ekstraksi Data
    for event in events:
        timestamp = event.get("timestamp")
        severity = event.get("severity", "").lower()
        source_ip = event.get("source_ip", "") # Ambil source_ip
        destination_ip = event.get("destination_ip", "") # Ambil destination_ip
        
        # A. Filter Severity (Sesuai kode asli, mencari event yang severity-nya BUKAN critical atau high)
        if severity in ["critical", "high"]:
            continue # Lewati jika severity adalah Critical atau High
            
        # ----------------------------------------------------------------------
        # B. 🆕 FILTER IP (Mengecualikan traffic internal 192.168.x.x ke 192.168.x.x)
        # ----------------------------------------------------------------------
        
        # Cek apakah Source IP dimulai dengan '192.168.'
        is_source_internal = source_ip.startswith("192.168.")
        
        # Cek apakah Destination IP dimulai dengan '192.168.'
        is_destination_internal = destination_ip.startswith("192.168.")
        
        # Traffic internal adalah jika KEDUA source DAN destination adalah 192.168.
        is_internal_traffic = is_source_internal and is_destination_internal
        
        if is_internal_traffic:
            continue # Lewati (skip) event ini karena merupakan traffic internal
        
        # ----------------------------------------------------------------------
        # C. Hanya proses event yang memiliki timestamp untuk sorting
        if timestamp is not None:
            # Ekstraksi semua data yang dibutuhkan
            events_with_timestamp.append({
                "destination_ip": destination_ip,
                "source_ip": source_ip,
                "country": event.get("country", ""), 
                "event_type": event.get("event_type", ""),
                "destination_country": event.get("destination_country", ""),
                "severity": event.get("severity", ""), # Simpan severity aslinya
                "timestamp": timestamp, # Digunakan untuk sorting
                "source_longitude": event.get("source_longitude"),
                "source_latitude": event.get("source_latitude"),
                "destination_longitude": event.get("destination_longitude"),
                "destination_latitude": event.get("destination_latitude"),
            })

    # 2. Sorting (Ambil 5 data terbaru)
    try:
        # Sortir berdasarkan 'timestamp' secara descending (terbaru)
        sorted_events = sorted(
            events_with_timestamp, 
            key=lambda x: x["timestamp"], 
            reverse=True
        )
    except (TypeError, KeyError):
        # Fallback jika timestamp formatnya bermasalah
        sorted_events = events_with_timestamp
        
    # 3. Ambil 5 data teratas
    return sorted_events[:5]

# ----------------------------
# 🔥 NEW FUNCTION – MITRE STATS
# ----------------------------
def calculate_mitre_stats(events):
    # total_events = len(events)

    # mitre_count = defaultdict(int)

    # for ev in events:
    #     stage = ev.get("mitre_stages")

    #     # skip null/None and "Unmapped"
    #     if not stage:
    #         continue
    #     if stage.lower() == "unmapped":
    #         continue

    #     mitre_count[stage] += 1

    # result = []
    # for stage, count in mitre_count.items():
    #     persen = (count / total_events * 100) if total_events > 0 else 0
    #     result.append({
    #         "stages": stage,
    #         "total_all": total_events,
    #         "total_data": count,
    #         "persen": f"{persen:.2f}"
    #     })

    # return result

    """
    Menghitung statistik MITRE ATT&CK untuk 5 stage yang ditentukan secara eksplisit,
    menambahkan field severity dan description untuk setiap stage.
    Stage yang tidak memiliki data tetap dimunculkan dengan total_data 0.
    """
    
    # 1. Definisikan 5 stage yang wajib muncul dan mapping detailnya (Severity & Description)
    STAGE_DETAILS_MAPPING = {
        "Initial Attempts": {
            "severity": "low",
            "description": "Reconnaissance, Initial Access"
        }, 
        "Persistent Foothold": {
            "severity": "medium",
            "description": "Execution, Persistence, Privilege Escalation"
        }, 
        "Exploration": {
            "severity": "medium",
            "description": "Defense Evasion, Credential Access, Discovery"
        }, 
        "Propagation": {
            "severity": "high",
            "description": "Lateral Movement"
        }, 
        "Exfiltration": {
            "severity": "critical",
            "description": "Collection, Exfiltration, Impact"
        }
    }
    
    # Ambil list nama stage yang wajib muncul dari keys mapping
    REQUIRED_STAGES = list(STAGE_DETAILS_MAPPING.keys())
    
    total_events = len(events)
    mitre_count = defaultdict(int)

    # 2. Hitung frekuensi event untuk stage yang ADA
    for ev in events:
        stage = ev.get("mitre_stages")

        # skip null/None and "Unmapped"
        if not stage:
            continue
        if stage.lower() == "unmapped":
            continue
            
        # Tambahkan ke hitungan hanya jika stage tersebut termasuk dalam 5 yang dibutuhkan
        if stage in REQUIRED_STAGES:
            mitre_count[stage] += 1

    result = []
    
    # 3. Iterasi melalui 5 stage yang WAJIB dimunculkan
    for stage in REQUIRED_STAGES:
        # Ambil hitungan dari mitre_count, default ke 0 jika tidak ditemukan
        count = mitre_count.get(stage, 0)
        
        # Hitung persentase
        persen_value = (count / total_events * 100) if total_events > 0 else 0
        
        # Dapatkan detail (severity dan description) dari mapping
        stage_detail = STAGE_DETAILS_MAPPING[stage]
        
        result.append({
            "stages": stage,
            "total_all": total_events,
            "total_data": count,
            "persen": f"{persen_value:.2f}",
            "severity": stage_detail["severity"],          # <-- AMBIL DARI DETAIL
            "description": stage_detail["description"]      # <-- FIELD BARU DITAMBAHKAN DI SINI
        })

    return result


def build_dynamic_filters(filters: List[FilterItem]):
    es_filters = []

    for f in filters:

        # Operator exact match
        if f.operator == "is":
            es_filters.append({"term": {f.field: f.value}})

        # Operator wildcard (contains)
        elif f.operator == "contains":
            es_filters.append({"wildcard": {f.field: f"*{f.value}*"}})

        # Prefix match
        elif f.operator == "starts_with":
            es_filters.append({"prefix": {f.field: f.value}})

        # Range gte
        elif f.operator == "gte":
            es_filters.append({"range": {f.field: {"gte": f.value}}})

        # Range lte
        elif f.operator == "lte":
            es_filters.append({"range": {f.field: {"lte": f.value}}})

        # IP CIDR match
        elif f.operator == "cidr":
            es_filters.append({"term": {f.field: f.value}})

    return es_filters