from datetime import datetime, timedelta
from .elastic_client import es
from .database import SessionLocal
from .models import CountIP
from sqlalchemy.orm import Session
import os

INDEX = os.getenv("ELASTIC_INDEX")
INDEX_PANW = ".ds-logs-panw.panos-default-*"

def get_time_range_filter(timeframe: str):
    now = datetime.utcnow()
    if timeframe == "yesterday":
        start = now - timedelta(days=1)
    elif timeframe == "8hours" or timeframe == "last8hours":
        start = now - timedelta(hours=8)
    elif timeframe == "24hours" or timeframe == "last24hours":
        start = now - timedelta(hours=24)
    elif timeframe == "last3days":
        start = now - timedelta(days=3)
    elif timeframe == "last7days":
        start = now - timedelta(days=7)
    elif timeframe == "last20days":
        start = now - timedelta(days=20)
    elif timeframe == "last90days":
        start = now - timedelta(days=90)
    else:
        start = now - timedelta(days=1)
    return {"range": {"@timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}}

def get_threat_counts(timeframe: str):
    # query = {
    #     "size": 0,
    #     "query": {
    #         "bool": {
    #             "filter": [
    #                 get_time_range_filter(timeframe),
    #                 {"term": {"event.module": "suricata"}}
    #             ]
    #         }
    #     },
    #     "aggs": {
    #         "by_rule": {
    #             "terms": {"field": "rule.name.keyword", "size": 1000},
    #             "aggs": {
    #                 "sample_event": {
    #                     "top_hits": {
    #                         "size": 1,
    #                         "sort": [
    #                         {"@timestamp": {"order": "desc"}}
    #                         ],  
    #                         "_source": [
    #                             "source.ip",
    #                             "destination.ip",
    #                             "rule.category",
    #                             "destination.geo.country_name",
    #                             "event.severity_label",
    #                             "destination.port",
    #                             "@timestamp"
    #                         ]
    #                     }
    #                 },
                    #Tambahan: ambil waktu pertama dan terakhir event
    #                 "first_event": {"min": {"field": "@timestamp"}},
    #                 "last_event": {"max": {"field": "@timestamp"}}
    #             }
    #         }
    #     }
    # }
    

    # res = es.search(index=INDEX, body=query)

    # results = []
    # for bucket in res["aggregations"]["by_rule"]["buckets"]:
    #     hit = bucket["sample_event"]["hits"]["hits"][0]["_source"] if bucket["sample_event"]["hits"]["hits"] else {}

    #     results.append({
    #         "rule_name": bucket["key"],
    #         "module": "suricata",
    #         "sub_type": hit.get("rule", {}).get("category"),
    #         "tipe": "No",
    #         "source_ip": hit.get("source", {}).get("ip"),
    #         "destination_ip": hit.get("destination", {}).get("ip"),
    #         "destination_geo_country_name": hit.get("destination", {}).get("geo", {}).get("country_name"),
    #         "event_severity_label": hit.get("event", {}).get("severity_label"),
    #         "destination_port": hit.get("destination", {}).get("port"),
    #         "count": bucket["doc_count"],
    #         "first_event": bucket["first_event"]["value_as_string"] if bucket["first_event"].get("value_as_string") else None,
    #         "last_event": bucket["last_event"]["value_as_string"] if bucket["last_event"].get("value_as_string") else None,
    #     })

    # return results

    #Data Sophos
    
    # query = {
    #     "size": 500,  
    #     "query": {
    #         "bool": {
    #             "filter": [
    #                 get_time_range_filter(timeframe),
    #                 {"term": {"event.module": "sophos"}},
    #                 {"term": {"sophos.xg.log_type": "Content Filtering"}}
    #             ]
    #         }
    #     },
    #     "sort": [
    #         {"@timestamp": {"order": "desc"}}
    #     ]
    # }

    # res = es.search(index=INDEX, body=query)
    # hits = res.get("hits", {}).get("hits", [])
    # results = []

    # for h in hits:
    #     src = h["_source"]
    #     sophos = src.get("sophos", {}).get("xg", {})

    #    mapping rule_name
        # rule_name = (
        #     sophos.get("message") #rule_name IDP
        #     or sophos.get("rule_name") #rule_name Content Filtering
        #     or "unknown"
        # )

        # results.append({
        #     "rule_name": rule_name,
        #     "module": "sophos",
        #     "sub_type": sophos.get("log_type"),
        #     "tipe": "No",
        #     "source_ip": src.get("source", {}).get("ip"),
        #     "destination_ip": src.get("destination", {}).get("ip"),
        #     "destination_geo_country_name": src.get("destination", {}).get("geo", {}).get("country_name"),
        #     "event_severity_label": src.get("event", {}).get("severity_label") or src.get("log", {}).get("level"),
        #     "destination_port": src.get("destination", {}).get("port") or sophos.get("dst_port"),
            
            # raw hits = count 1
        #    "count": 1,

            # timestamps sama (karena raw)
    #           "first_event": src.get("@timestamp"),
    #           "last_event": src.get("@timestamp"),
    #       })

    # return results

    #Data Panw

    query = {
        "size": 500,
        "query": {
            "bool": {
                "filter": [
                    get_time_range_filter(timeframe),
                    {"term": {"event.module": "panw"}},
                    {"term": {"panw.panos.type": "THREAT"}},
                    {"term": {"panw.panos.sub_type": "file"}}
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
    #       "rule_name": panw.get("ruleset") or panw.get("threat", {}).get("name") or "unknown", # tipe Content Filtering
            "rule_name": panw.get("threat", {}).get("name"),
            "module": "panw",
            "sub_type": panw.get("sub_type"),
            "tipe": panw.get("type"),
            "action": panw.get("action"),
            "source_ip": src.get("source", {}).get("ip"),
            "destination_ip": src.get("destination", {}).get("ip"),
            "destination_geo_country_name": src.get("destination", {}).get("geo", {}).get("country_name"),
            "event_severity_label": src.get("log", {}).get("syslog", {}).get("severity", {}).get("name"),
            "destination_port": src.get("destination", {}).get("port"),

            # setiap hit = count 1
            "count": 1,

            "first_event": src.get("@timestamp"),
            "last_event": src.get("@timestamp")
        })

    return results  




# ======================
# SIMPAN KE DATABASE
# ======================
def save_to_db(results, db: Session):
    try:
        for item in results:
            record = CountIP(
                rule_name=item["rule_name"],
                source_ip=item.get("source_ip"),
                destination_ip=item.get("destination_ip"),
                destination_geo_country=item.get("destination_geo_country_name"),
                event_severity_label=item.get("event_severity_label"),
                destination_port=item.get("destination_port"),
                counts=item.get("count"),
                first_seen_event=item["first_event"],
                last_seen_event=item["last_event"],
                modul=item["module"],
                sub_type=item["sub_type"],
                tipe=item["tipe"]

            )
            db.add(record)
        db.commit()
        print(f"✅ {len(results)} records berhasil disimpan ke database.")
    except Exception as e:
        db.rollback()
        print(f"❌ Error saat menyimpan ke DB: {e}")


# ======================
# CONTOH PENGGUNAAN
# ======================
# if __name__ == "__main__":
#     timeframe = "last7days"  # bisa diubah
#     data = get_threat_counts(timeframe)
#     save_to_db(data)
