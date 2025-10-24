from sqlalchemy import Column, String, BigInteger, TIMESTAMP
from app.database import Base
import uuid
from datetime import datetime
from zoneinfo import ZoneInfo

def generate_id():
    return "-".join([uuid.uuid4().hex[:4] for _ in range(4)])

def now_jakarta():
    # Menggunakan Asia/Jakarta dengan fallback ke UTC
    try:
        return datetime.now(ZoneInfo("Asia/Jakarta"))
    except Exception:
        return datetime.utcnow()

class CountIP(Base):
    __tablename__ = "countip"

    id = Column(String, primary_key=True, default=generate_id)
    rule_name = Column(String)
    source_ip = Column(String)
    destination_ip = Column(String)
    destination_geo_country = Column(String)
    event_severity_label = Column(String)
    destination_port = Column(String)
    counts = Column(BigInteger)
    created_date = Column(TIMESTAMP, default=now_jakarta)
    first_seen_event = Column(TIMESTAMP, default=datetime.utcnow)
    last_seen_event = Column(TIMESTAMP, default=datetime.utcnow)
