"""
Registry of all available collectors.

Import this module to get a list of collector instances to iterate over.
"""
from app.collectors.abuseipdb import AbuseIPDBCollector
from app.collectors.feodo import FeodoTrackerCollector
from app.collectors.otx import OTXCollector

ALL_COLLECTORS = [
    OTXCollector(),
    AbuseIPDBCollector(),
    FeodoTrackerCollector(),
]

__all__ = ["ALL_COLLECTORS", "OTXCollector", "AbuseIPDBCollector", "FeodoTrackerCollector"]
