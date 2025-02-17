from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, Text, Float

Base = declarative_base()

class ExtractedFeature(Base):
    __tablename__ = "extracted_features"

    id = Column(Integer, primary_key=True, index=True)
    request_method = Column(String, nullable=True)
    url_pattern = Column(String, nullable=True)
    alert_type = Column(String, nullable=True)
    response_headers = Column(Text, nullable=True)
    response_body = Column(Text, nullable=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String, nullable=True)
    reference_urls = Column(Text, nullable=True)


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    cve_id = Column(String, unique=True, nullable=False)
    description = Column(String, nullable=False)
    cvss_score = Column(Float, nullable=False)
    severity = Column(String, nullable=False)
    references = Column(Text, nullable=True)