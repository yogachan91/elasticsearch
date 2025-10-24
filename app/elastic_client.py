import os
import urllib3
from elasticsearch import Elasticsearch, RequestsHttpConnection
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv

# Matikan warning SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
load_dotenv()

ELASTIC_HOST = os.getenv("ELASTIC_HOST")
ELASTIC_USER = os.getenv("ELASTIC_USER")
ELASTIC_PASSWORD = os.getenv("ELASTIC_PASSWORD")

print(f"Connecting to: {ELASTIC_HOST}")

try:
    # Gunakan connection class yang support requests + basic auth
    es = Elasticsearch(
        [ELASTIC_HOST],
        connection_class=RequestsHttpConnection,
        http_auth=(ELASTIC_USER, ELASTIC_PASSWORD),
        use_ssl=True,
        verify_certs=False
    )

    # Coba autentikasi
    user_info = es.transport.perform_request("GET", "/_security/_authenticate")
    print("✅ Connected as:", user_info["username"], "| Roles:", user_info["roles"])

except Exception as e:
    print("❌ Connection failed:", str(e))
