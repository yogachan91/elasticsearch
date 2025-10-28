from datetime import datetime, timedelta
from .elastic_client import es
from .database import SessionLocal
from .models import CountIP
from sqlalchemy.orm import Session
import os

INDEX = os.getenv("ELASTIC_INDEX")

def get_time_range_filter(timeframe: str):
    now = datetime.utcnow()
    if timeframe == "yesterday":
        start = now - timedelta(days=1)
    elif timeframe == "8hours" or timeframe == "last8hours":
        start = now - timedelta(hours=8)
    elif timeframe == "14hours" or timeframe == "last14hours":
        start = now - timedelta(hours=14)
    elif timeframe == "last3days":
        start = now - timedelta(days=3)
    elif timeframe == "last7days":
        start = now - timedelta(days=7)
    else:
        start = now - timedelta(days=1)
    return {"range": {"@timestamp": {"gte": start.isoformat(), "lte": now.isoformat()}}}

def get_threat_counts(timeframe: str):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    get_time_range_filter(timeframe),
                    {"term": {"tags": "alert"}}
                ]
            }
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.name.keyword", "size": 1000},
                "aggs": {
                    "sample_event": {
                        "top_hits": {
                            "size": 1,  # ambil 1 contoh dokumen per rule
                            "_source": [
                                "source.ip",
                                "destination.ip",
                                "destination.geo.country_name",
                                "event.severity_label",
                                "destination.port",
                                "@timestamp"
                            ]
                        }
                    },
                    # Tambahan: ambil waktu pertama dan terakhir event
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
            "rule_name": bucket["key"],
            "source_ip": hit.get("source", {}).get("ip"),
            "destination_ip": hit.get("destination", {}).get("ip"),
            "destination_geo_country_name": hit.get("destination", {}).get("geo", {}).get("country_name"),
            "event_severity_label": hit.get("event", {}).get("severity_label"),
            "destination_port": hit.get("destination", {}).get("port"),
            "count": bucket["doc_count"],
            "first_event": bucket["first_event"]["value_as_string"] if bucket["first_event"].get("value_as_string") else None,
            "last_event": bucket["last_event"]["value_as_string"] if bucket["last_event"].get("value_as_string") else None,
        })

    return results

def get_unique_source_ip_per_rule(timeframe: str):
    query = {
        "size": 0,
        "query": {
            "bool": {
                "filter": [
                    get_time_range_filter(timeframe),
                    {"term": {"tags": "alert"}}
                ]
            }
        },
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.name.keyword", "size": 100},
                "aggs": {
                    # hitung jumlah unique IP
                    "unique_source": {
                        "cardinality": {"field": "source.ip.keyword"}
                    },
                    # tampilkan daftar IP
                    "source_ips": {
                        "terms": {"field": "source.ip.keyword", "size": 1000},
                        "aggs": {
                            # ambil hostname per IP (kalau ada)
                            "hostnames": {
                                "terms": {"field": "source.hostname.keyword", "size": 100}
                            }
                        }
                    }
                }
            }
        }
    }

    res = es.search(index=INDEX, body=query)

    results = []
    for bucket in res["aggregations"]["by_rule"]["buckets"]:
        ip_list = []
        hostname_set = set()

        # Loop semua IP yang ditemukan
        for ip_bucket in bucket["source_ips"]["buckets"]:
            ip_list.append(ip_bucket["key"])
            # Loop hostname dari setiap IP
            for h_bucket in ip_bucket["hostnames"]["buckets"]:
                hostname_set.add(h_bucket["key"])

        results.append({
            "rule_name": bucket["key"],
            "hostnames": len(hostname_set),  # total unique hostname
            "source_IP": len(ip_list),       # total IP ditemukan
            "unique_source_ips": bucket["unique_source"]["value"],  # jumlah IP unik
            "unique_source_ips_list": ip_list  # daftar IP
        })

    return results

def get_top_destination_ip(timeframe: str):
    query = {
        "size": 0,
        "query": {"bool": {"filter": [get_time_range_filter(timeframe), {"term": {"tags": "alert"}}]}},
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.name.keyword", "size": 100},
                "aggs": {
                    "by_source": {
                        "terms": {"field": "source.ip.keyword", "size": 100},
                        "aggs": {
                            "top_dest": {"terms": {"field": "destination.ip.keyword", "size": 1}}
                        }
                    }
                }
            }
        }
    }
    res = es.search(index=INDEX, body=query)
    results = []
    for rule_bucket in res["aggregations"]["by_rule"]["buckets"]:
        rule_name = rule_bucket["key"]
        for src_bucket in rule_bucket["by_source"]["buckets"]:
            src_ip = src_bucket["key"]
            top_dest = src_bucket["top_dest"]["buckets"][0]["key"] if src_bucket["top_dest"]["buckets"] else None
            results.append({"rule_name": rule_name, "source_ip": src_ip, "top_destination_ip": top_dest})
    return results

def get_first_last_event(ip_address: str):
    query = {
        "size": 0,
        "query": {"term": {"source.ip.keyword": ip_address}},
        "aggs": {
            "by_rule": {
                "terms": {"field": "rule.name.keyword", "size": 100},
                "aggs": {
                    "first_event": {"min": {"field": "@timestamp"}},
                    "last_event": {"max": {"field": "@timestamp"}}
                }
            }
        }
    }
    res = es.search(index=INDEX, body=query)
    return [
        {
            "rule_name": b["key"],
            "first_event": b["first_event"]["value_as_string"],
            "last_event": b["last_event"]["value_as_string"],
        }
        for b in res["aggregations"]["by_rule"]["buckets"]
    ]


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
                last_seen_event=item["last_event"]
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
