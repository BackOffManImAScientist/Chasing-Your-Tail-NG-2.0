#!/usr/bin/env python3
"""
Stop Comparison Analyzer for Chasing Your Tail NG
Compares SSIDs, BSSIDs, and Probe Requests across multiple predetermined stops.

This module integrates with the existing CYT infrastructure to identify
devices that appear at 2 or more user-defined location stops.

Author: CYT Enhancement
License: MIT License
"""

import json
import os
import glob
import sqlite3
from datetime import datetime
from math import radians, sin, cos, sqrt, atan2
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict
import logging
import pathlib

# Try to import existing CYT modules for integration
try:
    from secure_credentials import secure_config_loader
    CYT_INTEGRATION = True
except ImportError:
    CYT_INTEGRATION = False

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


@dataclass
class Stop:
    """Represents a predetermined location stop."""
    name: str
    latitude: float
    longitude: float
    description: str = ""
    
    def __hash__(self):
        return hash((self.name, self.latitude, self.longitude))


@dataclass
class WirelessDevice:
    """Represents a wireless device or signal."""
    identifier: str
    identifier_type: str  # 'BSSID', 'SSID', or 'PROBE'
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    signal_strength: Optional[int] = None
    stops_seen: Set[str] = field(default_factory=set)
    # New fields for enhanced tracking
    timestamps_by_stop: Dict[str, List[datetime]] = field(default_factory=dict)
    signal_by_stop: Dict[str, int] = field(default_factory=dict)
    manufacturer: str = ""
    threat_score: float = 0.0
    
    def __hash__(self):
        return hash((self.identifier, self.identifier_type))


# OUI Database for manufacturer lookup (common vendors)
OUI_DATABASE = {
    "00:00:0C": "Cisco",
    "00:01:42": "Cisco",
    "00:03:93": "Apple",
    "00:05:02": "Apple",
    "00:0A:27": "Apple",
    "00:0A:95": "Apple",
    "00:0D:93": "Apple",
    "00:11:24": "Apple",
    "00:14:51": "Apple",
    "00:16:CB": "Apple",
    "00:17:F2": "Apple",
    "00:19:E3": "Apple",
    "00:1B:63": "Apple",
    "00:1C:B3": "Apple",
    "00:1D:4F": "Apple",
    "00:1E:52": "Apple",
    "00:1E:C2": "Apple",
    "00:1F:5B": "Apple",
    "00:1F:F3": "Apple",
    "00:21:E9": "Apple",
    "00:22:41": "Apple",
    "00:23:12": "Apple",
    "00:23:32": "Apple",
    "00:23:6C": "Apple",
    "00:23:DF": "Apple",
    "00:24:36": "Apple",
    "00:25:00": "Apple",
    "00:25:4B": "Apple",
    "00:25:BC": "Apple",
    "00:26:08": "Apple",
    "00:26:4A": "Apple",
    "00:26:B0": "Apple",
    "00:26:BB": "Apple",
    "00:30:65": "Apple",
    "00:3E:E1": "Apple",
    "00:50:E4": "Apple",
    "00:56:CD": "Apple",
    "00:61:71": "Apple",
    "00:6D:52": "Apple",
    "00:88:65": "Apple",
    "00:B3:62": "Apple",
    "00:C6:10": "Apple",
    "00:CD:FE": "Apple",
    "00:DB:70": "Apple",
    "00:F4:B9": "Apple",
    "00:F7:6F": "Apple",
    "04:0C:CE": "Apple",
    "04:15:52": "Apple",
    "04:26:65": "Apple",
    "04:48:9A": "Apple",
    "04:52:F3": "Apple",
    "04:54:53": "Apple",
    "04:D3:CF": "Apple",
    "04:DB:56": "Apple",
    "04:E5:36": "Apple",
    "04:F1:3E": "Apple",
    "04:F7:E4": "Apple",
    "08:00:07": "Apple",
    "08:66:98": "Apple",
    "08:70:45": "Apple",
    "08:74:02": "Apple",
    "10:40:F3": "Apple",
    "10:41:7F": "Apple",
    "10:9A:DD": "Apple",
    "10:DD:B1": "Apple",
    "14:10:9F": "Apple",
    "14:5A:05": "Apple",
    "14:8F:C6": "Apple",
    "14:99:E2": "Apple",
    "18:20:32": "Apple",
    "18:34:51": "Apple",
    "18:65:90": "Apple",
    "18:9E:FC": "Apple",
    "18:AF:61": "Apple",
    "18:AF:8F": "Apple",
    "18:E7:F4": "Apple",
    "18:EE:69": "Apple",
    "18:F6:43": "Apple",
    "1C:1A:C0": "Apple",
    "1C:36:BB": "Apple",
    "1C:5C:F2": "Apple",
    "1C:91:48": "Apple",
    "1C:9E:46": "Apple",
    "1C:AB:A7": "Apple",
    "1C:E6:2B": "Apple",
    "20:3C:AE": "Apple",
    "20:78:F0": "Apple",
    "20:7D:74": "Apple",
    "20:9B:CD": "Apple",
    "20:A2:E4": "Apple",
    "20:AB:37": "Apple",
    "20:C9:D0": "Apple",
    "24:1E:EB": "Apple",
    "24:24:0E": "Apple",
    "24:A0:74": "Apple",
    "24:A2:E1": "Apple",
    "24:AB:81": "Apple",
    "24:E3:14": "Apple",
    "24:F0:94": "Apple",
    "24:F6:77": "Apple",
    "28:0B:5C": "Apple",
    "28:37:37": "Apple",
    "28:5A:EB": "Apple",
    "28:6A:B8": "Apple",
    "28:6A:BA": "Apple",
    "28:A0:2B": "Apple",
    "28:CF:DA": "Apple",
    "28:CF:E9": "Apple",
    "28:E0:2C": "Apple",
    "28:E1:4C": "Apple",
    "28:E7:CF": "Apple",
    "28:ED:6A": "Apple",
    "28:F0:76": "Apple",
    "28:FF:3C": "Apple",
    "2C:1F:23": "Apple",
    "2C:20:0B": "Apple",
    "2C:33:61": "Apple",
    "2C:54:CF": "Apple",
    "2C:BE:08": "Apple",
    "2C:F0:A2": "Apple",
    "2C:F0:EE": "Apple",
    "30:10:E4": "Apple",
    "30:35:AD": "Apple",
    "30:63:6B": "Apple",
    "30:90:AB": "Apple",
    "30:F7:C5": "Apple",
    "34:08:BC": "Apple",
    "34:12:98": "Apple",
    "34:15:9E": "Apple",
    "34:36:3B": "Apple",
    "34:51:C9": "Apple",
    "34:A3:95": "Apple",
    "34:AB:37": "Apple",
    "34:C0:59": "Apple",
    "34:E2:FD": "Apple",
    "38:0F:4A": "Apple",
    "38:48:4C": "Apple",
    "38:53:9C": "Apple",
    "38:66:F0": "Apple",
    "38:71:DE": "Apple",
    "38:89:2C": "Apple",
    "38:8C:50": "Apple",
    "38:B5:4D": "Apple",
    "38:C9:86": "Apple",
    "38:CA:DA": "Apple",
    "3C:06:30": "Apple",
    "3C:07:71": "Apple",
    "3C:15:C2": "Apple",
    "3C:2E:F9": "Apple",
    "3C:2E:FF": "Apple",
    "00:12:17": "Cisco-Linksys",
    "00:14:BF": "Cisco-Linksys",
    "00:16:B6": "Cisco-Linksys",
    "00:18:39": "Cisco-Linksys",
    "00:18:F8": "Cisco-Linksys",
    "00:1A:70": "Cisco-Linksys",
    "00:1C:10": "Cisco-Linksys",
    "00:1D:7E": "Cisco-Linksys",
    "00:1E:E5": "Cisco-Linksys",
    "00:21:29": "Cisco-Linksys",
    "00:22:6B": "Cisco-Linksys",
    "00:23:69": "Cisco-Linksys",
    "00:25:9C": "Cisco-Linksys",
    "4C:32:75": "Apple",
    "50:EA:D6": "Apple",
    "54:26:96": "Apple",
    "54:4E:90": "Apple",
    "58:55:CA": "Apple",
    "5C:59:48": "Apple",
    "5C:F9:38": "Apple",
    "60:03:08": "Apple",
    "60:69:44": "Apple",
    "60:C5:47": "Apple",
    "60:D9:C7": "Apple",
    "60:F4:45": "Apple",
    "60:F8:1D": "Apple",
    "60:FA:CD": "Apple",
    "60:FE:C5": "Apple",
    "64:20:0C": "Apple",
    "64:4B:F0": "Apple",
    "64:76:BA": "Apple",
    "64:9A:BE": "Apple",
    "64:A3:CB": "Apple",
    "64:B0:A6": "Apple",
    "64:B9:E8": "Apple",
    "64:E6:82": "Apple",
    "68:09:27": "Apple",
    "68:5B:35": "Apple",
    "68:64:4B": "Apple",
    "68:96:7B": "Apple",
    "68:9C:70": "Apple",
    "68:A8:6D": "Apple",
    "68:AB:1E": "Apple",
    "68:AE:20": "Apple",
    "68:D9:3C": "Apple",
    "68:DB:CA": "Apple",
    "68:FB:7E": "Apple",
    "6C:19:C0": "Apple",
    "6C:3E:6D": "Apple",
    "6C:40:08": "Apple",
    "6C:70:9F": "Apple",
    "6C:72:E7": "Apple",
    "6C:8D:C1": "Apple",
    "6C:94:F8": "Apple",
    "6C:96:CF": "Apple",
    "6C:AB:31": "Apple",
    "6C:C2:6B": "Apple",
    "70:11:24": "Apple",
    "70:14:A6": "Apple",
    "70:3E:AC": "Apple",
    "70:48:0F": "Apple",
    "70:56:81": "Apple",
    "70:73:CB": "Apple",
    "70:81:EB": "Apple",
    "70:A2:B3": "Apple",
    "70:CD:60": "Apple",
    "70:DE:E2": "Apple",
    "70:E7:2C": "Apple",
    "70:EC:E4": "Apple",
    "70:F0:87": "Apple",
    "74:1B:B2": "Apple",
    "74:42:8B": "Apple",
    "74:8D:08": "Apple",
    "74:E1:B6": "Apple",
    "74:E2:F5": "Apple",
    "78:31:C1": "Apple",
    "78:3A:84": "Apple",
    "78:4F:43": "Apple",
    "78:67:D7": "Apple",
    "78:6C:1C": "Apple",
    "78:7E:61": "Apple",
    "78:88:6D": "Apple",
    "78:9F:70": "Apple",
    "78:A3:E4": "Apple",
    "78:CA:39": "Apple",
    "78:D7:5F": "Apple",
    "78:FD:94": "Apple",
    "7C:01:91": "Apple",
    "7C:04:D0": "Apple",
    "7C:11:BE": "Apple",
    "7C:6D:62": "Apple",
    "7C:6D:F8": "Apple",
    "7C:C3:A1": "Apple",
    "7C:C5:37": "Apple",
    "7C:D1:C3": "Apple",
    "7C:F0:5F": "Apple",
    "7C:FA:DF": "Apple",
    "80:00:6E": "Apple",
    "80:49:71": "Apple",
    "80:82:23": "Apple",
    "80:92:9F": "Apple",
    "80:B0:3D": "Apple",
    "80:E6:50": "Apple",
    "80:EA:96": "Apple",
    "80:ED:2C": "Apple",
    "84:29:99": "Apple",
    "84:38:35": "Apple",
    "84:78:8B": "Apple",
    "84:85:06": "Apple",
    "84:89:AD": "Apple",
    "84:8E:0C": "Apple",
    "84:A1:34": "Apple",
    "84:B1:53": "Apple",
    "84:FC:AC": "Apple",
    "84:FC:FE": "Apple",
    "88:19:08": "Apple",
    "88:1F:A1": "Apple",
    "88:53:95": "Apple",
    "88:63:DF": "Apple",
    "88:66:A5": "Apple",
    "88:6B:6E": "Apple",
    "88:C6:63": "Apple",
    "88:CB:87": "Apple",
    "88:E8:7F": "Apple",
    "8C:00:6D": "Apple",
    "8C:29:37": "Apple",
    "8C:2D:AA": "Apple",
    "8C:58:77": "Apple",
    "8C:7B:9D": "Apple",
    "8C:7C:92": "Apple",
    "8C:85:90": "Apple",
    "8C:8E:F2": "Apple",
    "8C:FA:BA": "Apple",
    "90:27:E4": "Apple",
    "90:3C:92": "Apple",
    "90:60:F1": "Apple",
    "90:72:40": "Apple",
    "90:84:0D": "Apple",
    "90:8D:6C": "Apple",
    "90:B0:ED": "Apple",
    "90:B2:1F": "Apple",
    "90:B9:31": "Apple",
    "90:C1:C6": "Apple",
    "90:FD:61": "Apple",
    "94:94:26": "Apple",
    "94:E9:6A": "Apple",
    "94:F6:A3": "Apple",
    "98:01:A7": "Apple",
    "98:03:D8": "Apple",
    "98:10:E8": "Apple",
    "98:5A:EB": "Apple",
    "98:B8:E3": "Apple",
    "98:CA:33": "Apple",
    "98:D6:BB": "Apple",
    "98:E0:D9": "Apple",
    "98:F0:AB": "Apple",
    "98:FE:94": "Apple",
    "9C:04:EB": "Apple",
    "9C:20:7B": "Apple",
    "9C:29:3F": "Apple",
    "9C:35:EB": "Apple",
    "9C:4F:DA": "Apple",
    "9C:84:BF": "Apple",
    "9C:8B:A0": "Apple",
    "9C:E3:3F": "Apple",
    "9C:F3:87": "Apple",
    "9C:FC:01": "Apple",
    "A0:18:28": "Apple",
    "A0:3B:E3": "Apple",
    "A0:4E:A7": "Apple",
    "A0:D7:95": "Apple",
    "A0:ED:CD": "Apple",
    "A0:F4:59": "Apple",
    "A4:31:35": "Apple",
    "A4:5E:60": "Apple",
    "A4:67:06": "Apple",
    "A4:83:E7": "Apple",
    "A4:B1:97": "Apple",
    "A4:B8:05": "Apple",
    "A4:C3:61": "Apple",
    "A4:D1:8C": "Apple",
    "A4:D1:D2": "Apple",
    "A4:E9:75": "Apple",
    "A4:F1:E8": "Apple",
    "A8:20:66": "Apple",
    "A8:5B:78": "Apple",
    "A8:5C:2C": "Apple",
    "A8:66:7F": "Apple",
    "A8:86:DD": "Apple",
    "A8:88:08": "Apple",
    "A8:8E:24": "Apple",
    "A8:96:8A": "Apple",
    "A8:BB:CF": "Apple",
    "A8:BE:27": "Apple",
    "A8:FA:D8": "Apple",
    "AC:1F:74": "Apple",
    "AC:29:3A": "Apple",
    "AC:3C:0B": "Apple",
    "AC:61:EA": "Apple",
    "AC:7F:3E": "Apple",
    "AC:87:A3": "Apple",
    "AC:BC:32": "Apple",
    "AC:CF:5C": "Apple",
    "AC:E4:B5": "Apple",
    "AC:FD:EC": "Apple",
    "B0:19:C6": "Apple",
    "B0:34:95": "Apple",
    "B0:48:1A": "Apple",
    "B0:65:BD": "Apple",
    "B0:70:2D": "Apple",
    "B0:9F:BA": "Apple",
    "B4:18:D1": "Apple",
    "B4:4B:D2": "Apple",
    "B4:8B:19": "Apple",
    "B4:9C:DF": "Apple",
    "B4:F0:AB": "Apple",
    "B4:F6:1C": "Apple",
    "B8:09:8A": "Apple",
    "B8:17:C2": "Apple",
    "B8:41:A4": "Apple",
    "B8:44:D9": "Apple",
    "B8:53:AC": "Apple",
    "B8:5A:F7": "Apple",
    "B8:63:4D": "Apple",
    "B8:78:2E": "Apple",
    "B8:8D:12": "Apple",
    "B8:C1:11": "Apple",
    "B8:C7:5D": "Apple",
    "B8:E8:56": "Apple",
    "B8:F6:B1": "Apple",
    "B8:FF:61": "Apple",
    "BC:3B:AF": "Apple",
    "BC:4C:C4": "Apple",
    "BC:52:B7": "Apple",
    "BC:54:36": "Apple",
    "BC:67:78": "Apple",
    "BC:6C:21": "Apple",
    "BC:76:70": "Apple",
    "BC:92:6B": "Apple",
    "BC:9F:EF": "Apple",
    "BC:A9:20": "Apple",
    "BC:EC:5D": "Apple",
    "BC:FE:D9": "Apple",
    "C0:1A:DA": "Apple",
    "C0:2C:5C": "Apple",
    "C0:63:94": "Apple",
    "C0:84:7A": "Apple",
    "C0:9F:42": "Apple",
    "C0:A5:3E": "Apple",
    "C0:CC:F8": "Apple",
    "C0:CE:CD": "Apple",
    "C0:D0:12": "Apple",
    "C0:F2:FB": "Apple",
    "C4:2C:03": "Apple",
    "C4:B3:01": "Apple",
    "C8:1E:E7": "Apple",
    "C8:2A:14": "Apple",
    "C8:33:4B": "Apple",
    "C8:3C:85": "Apple",
    "C8:69:CD": "Apple",
    "C8:6F:1D": "Apple",
    "C8:85:50": "Apple",
    "C8:B5:B7": "Apple",
    "C8:BC:C8": "Apple",
    "C8:D0:83": "Apple",
    "C8:E0:EB": "Apple",
    "C8:F6:50": "Apple",
    "CC:08:8D": "Apple",
    "CC:20:E8": "Apple",
    "CC:25:EF": "Apple",
    "CC:29:F5": "Apple",
    "CC:44:63": "Apple",
    "CC:78:5F": "Apple",
    "CC:C7:60": "Apple",
    "D0:03:4B": "Apple",
    "D0:23:DB": "Apple",
    "D0:25:98": "Apple",
    "D0:33:11": "Apple",
    "D0:4F:7E": "Apple",
    "D0:A6:37": "Apple",
    "D0:C5:F3": "Apple",
    "D0:E1:40": "Apple",
    "D4:61:9D": "Apple",
    "D4:9A:20": "Apple",
    "D4:DC:CD": "Apple",
    "D4:F4:6F": "Apple",
    "D8:00:4D": "Apple",
    "D8:1D:72": "Apple",
    "D8:30:62": "Apple",
    "D8:8F:76": "Apple",
    "D8:96:95": "Apple",
    "D8:9E:3F": "Apple",
    "D8:A2:5E": "Apple",
    "D8:BB:2C": "Apple",
    "D8:CF:9C": "Apple",
    "D8:D1:CB": "Apple",
    "DC:0C:5C": "Apple",
    "DC:2B:2A": "Apple",
    "DC:2B:61": "Apple",
    "DC:37:14": "Apple",
    "DC:41:5F": "Apple",
    "DC:56:E7": "Apple",
    "DC:86:D8": "Apple",
    "DC:9B:9C": "Apple",
    "DC:A4:CA": "Apple",
    "DC:A9:04": "Apple",
    "E0:5F:45": "Apple",
    "E0:66:78": "Apple",
    "E0:AC:CB": "Apple",
    "E0:B5:2D": "Apple",
    "E0:B9:BA": "Apple",
    "E0:C7:67": "Apple",
    "E0:C9:7A": "Apple",
    "E0:F5:C6": "Apple",
    "E0:F8:47": "Apple",
    "E4:25:E7": "Apple",
    "E4:2B:34": "Apple",
    "E4:8B:7F": "Apple",
    "E4:98:D6": "Apple",
    "E4:9A:79": "Apple",
    "E4:9A:DC": "Apple",
    "E4:C6:3D": "Apple",
    "E4:CE:8F": "Apple",
    "E4:E4:AB": "Apple",
    "E8:04:0B": "Apple",
    "E8:06:88": "Apple",
    "E8:80:2E": "Apple",
    "E8:8D:28": "Apple",
    "EC:35:86": "Apple",
    "EC:85:2F": "Apple",
    "F0:18:98": "Apple",
    "F0:24:75": "Apple",
    "F0:79:60": "Apple",
    "F0:99:B6": "Apple",
    "F0:99:BF": "Apple",
    "F0:B0:E7": "Apple",
    "F0:C1:F1": "Apple",
    "F0:CB:A1": "Apple",
    "F0:D1:A9": "Apple",
    "F0:DB:E2": "Apple",
    "F0:DC:E2": "Apple",
    "F0:F6:1C": "Apple",
    "F4:0F:24": "Apple",
    "F4:1B:A1": "Apple",
    "F4:31:C3": "Apple",
    "F4:37:B7": "Apple",
    "F4:5C:89": "Apple",
    "F4:F1:5A": "Apple",
    "F4:F9:51": "Apple",
    "F8:03:32": "Apple",
    "F8:1E:DF": "Apple",
    "F8:27:93": "Apple",
    "F8:62:14": "Apple",
    "F8:95:EA": "Apple",
    "FC:25:3F": "Apple",
    "FC:D8:48": "Apple",
    "FC:E9:98": "Apple",
    "FC:FC:48": "Apple",
    # Samsung
    "00:00:F0": "Samsung",
    "00:02:78": "Samsung",
    "00:09:18": "Samsung",
    "00:0D:AE": "Samsung",
    "00:12:47": "Samsung",
    "00:12:FB": "Samsung",
    "00:13:77": "Samsung",
    "00:15:99": "Samsung",
    "00:15:B9": "Samsung",
    "00:16:32": "Samsung",
    "00:16:6B": "Samsung",
    "00:16:6C": "Samsung",
    "00:16:DB": "Samsung",
    "00:17:C9": "Samsung",
    "00:17:D5": "Samsung",
    "00:18:AF": "Samsung",
    "00:1A:8A": "Samsung",
    "00:1B:98": "Samsung",
    "00:1C:43": "Samsung",
    "00:1D:25": "Samsung",
    "00:1D:F6": "Samsung",
    "00:1E:7D": "Samsung",
    "00:1F:CC": "Samsung",
    "00:1F:CD": "Samsung",
    "00:21:19": "Samsung",
    "00:21:4C": "Samsung",
    "00:21:D1": "Samsung",
    "00:21:D2": "Samsung",
    "00:23:39": "Samsung",
    "00:23:3A": "Samsung",
    "00:23:99": "Samsung",
    "00:23:D6": "Samsung",
    "00:23:D7": "Samsung",
    "00:24:54": "Samsung",
    "00:24:90": "Samsung",
    "00:24:91": "Samsung",
    "00:24:E9": "Samsung",
    "00:25:38": "Samsung",
    "00:25:66": "Samsung",
    "00:25:67": "Samsung",
    "00:26:37": "Samsung",
    "00:26:5D": "Samsung",
    "00:26:5F": "Samsung",
    "5C:0A:5B": "Samsung",
    "5C:3C:27": "Samsung",
    "84:25:DB": "Samsung",
    "8C:77:12": "Samsung",
    "94:35:0A": "Samsung",
    "A8:06:00": "Samsung",
    "BC:44:86": "Samsung",
    "C4:42:02": "Samsung",
    "E4:7C:F9": "Samsung",
    "EC:1F:72": "Samsung",
    "F4:7B:5E": "Samsung",
    # Google
    "00:1A:11": "Google",
    "3C:5A:B4": "Google",
    "54:60:09": "Google",
    "94:EB:2C": "Google",
    "F4:F5:D8": "Google",
    "F4:F5:E8": "Google",
    # Intel
    "00:02:B3": "Intel",
    "00:03:47": "Intel",
    "00:04:23": "Intel",
    "00:07:E9": "Intel",
    "00:0C:F1": "Intel",
    "00:0E:0C": "Intel",
    "00:0E:35": "Intel",
    "00:11:11": "Intel",
    "00:12:F0": "Intel",
    "00:13:02": "Intel",
    "00:13:20": "Intel",
    "00:13:CE": "Intel",
    "00:13:E8": "Intel",
    "00:15:00": "Intel",
    "00:15:17": "Intel",
    "00:16:6F": "Intel",
    "00:16:76": "Intel",
    "00:16:EA": "Intel",
    "00:16:EB": "Intel",
    "00:18:DE": "Intel",
    "00:19:D1": "Intel",
    "00:19:D2": "Intel",
    "00:1B:21": "Intel",
    "00:1B:77": "Intel",
    "00:1C:BF": "Intel",
    "00:1C:C0": "Intel",
    "00:1D:E0": "Intel",
    "00:1D:E1": "Intel",
    "00:1E:64": "Intel",
    "00:1E:65": "Intel",
    "00:1E:67": "Intel",
    "00:1F:3B": "Intel",
    "00:1F:3C": "Intel",
    "00:20:E0": "Intel",
    "00:21:5C": "Intel",
    "00:21:5D": "Intel",
    "00:21:6A": "Intel",
    "00:21:6B": "Intel",
    "00:22:FA": "Intel",
    "00:22:FB": "Intel",
    "00:23:14": "Intel",
    "00:23:15": "Intel",
    "00:24:D6": "Intel",
    "00:24:D7": "Intel",
    "00:26:C6": "Intel",
    "00:26:C7": "Intel",
    "00:26:C8": "Intel",
    "00:27:10": "Intel",
    "34:02:86": "Intel",
    "5C:51:4F": "Intel",
    "64:80:99": "Intel",
    "68:17:29": "Intel",
    "74:E5:43": "Intel",
    "7C:5C:F8": "Intel",
    "84:3A:4B": "Intel",
    "8C:70:5A": "Intel",
    "AC:7B:A1": "Intel",
    "B4:6B:FC": "Intel",
    "D4:3D:7E": "Intel",
    "F8:16:54": "Intel",
    # TP-Link
    "00:1D:0F": "TP-Link",
    "14:CC:20": "TP-Link",
    "14:CF:92": "TP-Link",
    "18:A6:F7": "TP-Link",
    "1C:3B:F3": "TP-Link",
    "30:B5:C2": "TP-Link",
    "50:C7:BF": "TP-Link",
    "54:C8:0F": "TP-Link",
    "60:E3:27": "TP-Link",
    "64:66:B3": "TP-Link",
    "64:70:02": "TP-Link",
    "6C:B0:CE": "TP-Link",
    "78:44:76": "TP-Link",
    "90:F6:52": "TP-Link",
    "94:0C:6D": "TP-Link",
    "98:DA:C4": "TP-Link",
    "A0:F3:C1": "TP-Link",
    "AC:84:C6": "TP-Link",
    "B0:4E:26": "TP-Link",
    "B0:BE:76": "TP-Link",
    "C0:25:E9": "TP-Link",
    "C4:6E:1F": "TP-Link",
    "C8:3A:35": "TP-Link",
    "D4:6E:0E": "TP-Link",
    "E8:DE:27": "TP-Link",
    "EC:08:6B": "TP-Link",
    "F4:F2:6D": "TP-Link",
    "F8:1A:67": "TP-Link",
    # Netgear
    "00:09:5B": "Netgear",
    "00:0F:B5": "Netgear",
    "00:14:6C": "Netgear",
    "00:18:4D": "Netgear",
    "00:1B:2F": "Netgear",
    "00:1E:2A": "Netgear",
    "00:1F:33": "Netgear",
    "00:22:3F": "Netgear",
    "00:24:B2": "Netgear",
    "00:26:F2": "Netgear",
    "20:4E:7F": "Netgear",
    "28:C6:8E": "Netgear",
    "2C:B0:5D": "Netgear",
    "30:46:9A": "Netgear",
    "44:94:FC": "Netgear",
    "4C:60:DE": "Netgear",
    "6C:B0:CE": "Netgear",
    "84:1B:5E": "Netgear",
    "8C:3B:AD": "Netgear",
    "9C:3D:CF": "Netgear",
    "A0:04:60": "Netgear",
    "A0:21:B7": "Netgear",
    "A0:40:A0": "Netgear",
    "A4:2B:8C": "Netgear",
    "B0:39:56": "Netgear",
    "B0:7F:B9": "Netgear",
    "C0:3F:0E": "Netgear",
    "C0:FF:D4": "Netgear",
    "C4:04:15": "Netgear",
    "C4:3D:C7": "Netgear",
    "CC:40:D0": "Netgear",
    "D8:EB:97": "Netgear",
    "DC:EF:09": "Netgear",
    "E0:46:9A": "Netgear",
    "E0:91:F5": "Netgear",
    "E4:F4:C6": "Netgear",
    "E8:FC:AF": "Netgear",
    "F8:73:94": "Netgear",
    "FC:FB:FB": "Netgear",
    # Huawei
    "00:1E:10": "Huawei",
    "00:25:68": "Huawei",
    "00:25:9E": "Huawei",
    "00:34:FE": "Huawei",
    "00:46:4B": "Huawei",
    "00:66:4B": "Huawei",
    "00:9A:CD": "Huawei",
    "00:E0:FC": "Huawei",
    "04:02:1F": "Huawei",
    "04:25:C5": "Huawei",
    "04:BD:70": "Huawei",
    "04:C0:6F": "Huawei",
    "04:F9:38": "Huawei",
    "04:FE:8D": "Huawei",
    "08:19:A6": "Huawei",
    "08:63:61": "Huawei",
    "08:7A:4C": "Huawei",
    "08:E8:4F": "Huawei",
    "0C:37:DC": "Huawei",
    "0C:45:BA": "Huawei",
    "0C:96:BF": "Huawei",
    "10:1B:54": "Huawei",
    "10:44:00": "Huawei",
    "10:47:80": "Huawei",
    "14:30:04": "Huawei",
    "14:57:9F": "Huawei",
    "14:A5:1A": "Huawei",
    "14:B9:68": "Huawei",
    "18:C5:8A": "Huawei",
    "18:D2:76": "Huawei",
    "1C:1D:67": "Huawei",
    "1C:8E:5C": "Huawei",
    "20:08:ED": "Huawei",
    "20:0B:C7": "Huawei",
    # Add more as needed
}

# Common carrier/public SSIDs to auto-filter
COMMON_PUBLIC_SSIDS = {
    "xfinitywifi", "XFINITY", "Xfinity Mobile", "xfinity",
    "ATT-WIFI", "attwifi", "AT&T Wi-Fi",
    "T-Mobile", "T-Mobile_5G", "T-Mobile Hotspot",
    "Verizon", "VerizonWiFi",
    "CableWiFi", "cablewifi",
    "Google Starbucks", "Starbucks WiFi",
    "McDonald's Free WiFi", "McDonalds Free WiFi",
    "Walmart WiFi", "WalmartWiFi",
    "TARGET-WIFI", "Target WiFi",
    "SUBWAY", "Subway WiFi",
    "Panera", "Panera Bread",
    "ChickfilA_WiFi", "Chick-fil-A WiFi",
    "Hilton Honors", "Marriott_Guest", "HolidayInn",
    "Delta_WiFi", "golounge", "AA-Inflight",
    "United_Wi-Fi", "Southwest WiFi",
    "HPE-Guest", "Guest", "GUEST",
    "Airport WiFi", "FreeAirportWifi",
    "linksys", "NETGEAR", "default", "SETUP",
    "HOME-", "MySpectrumWiFi", "SpectrumSetup",
    "optimumwifi", "CenturyLink",
}


class StopComparisonAnalyzer:
    """
    Analyzes wireless data across multiple predetermined stops to identify
    devices/networks that appear at multiple locations (potential surveillance indicators).
    """
    
    def __init__(self, config_path: str = "config.json"):
        """Initialize the analyzer with configuration."""
        self.config = self._load_config(config_path)
        self.stops: List[Stop] = []
        self.radius_meters: float = 100
        self.minimum_occurrences: int = 2
        
        # Data structures for collected wireless info
        self.bssids_by_stop: Dict[str, Set[str]] = defaultdict(set)
        self.ssids_by_stop: Dict[str, Set[str]] = defaultdict(set)
        self.probes_by_stop: Dict[str, Set[str]] = defaultdict(set)
        
        # Detailed device tracking
        self.devices: Dict[str, WirelessDevice] = {}
        
        # Ignore lists
        self.ignored_macs: Set[str] = set()
        self.ignored_ssids: Set[str] = set()
        
        self._parse_stop_config()
        self._load_ignore_lists()
    
    def _load_config(self, config_path: str) -> dict:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Config file not found: {config_path}")
            raise
        except json.JSONDecodeError as e:
            logger.error(f"Invalid JSON in config file: {e}")
            raise
    
    def _parse_stop_config(self):
        """Parse stop comparison configuration."""
        stop_config = self.config.get('stop_comparison', {})
        
        if not stop_config.get('enabled', False):
            logger.warning("Stop comparison is not enabled in config")
            return
        
        self.radius_meters = stop_config.get('radius_meters', 100)
        self.minimum_occurrences = stop_config.get('minimum_occurrences', 2)
        
        stops_data = stop_config.get('stops', [])
        
        if len(stops_data) < 2:
            logger.warning("At least 2 stops are required for comparison")
        elif len(stops_data) > 5:
            logger.warning("Maximum 5 stops supported, using first 5")
            stops_data = stops_data[:5]
        
        for stop_data in stops_data:
            try:
                stop = Stop(
                    name=stop_data['name'],
                    latitude=float(stop_data['latitude']),
                    longitude=float(stop_data['longitude']),
                    description=stop_data.get('description', '')
                )
                self.stops.append(stop)
                logger.info(f"Loaded stop: {stop.name} ({stop.latitude}, {stop.longitude})")
            except (KeyError, ValueError) as e:
                logger.error(f"Invalid stop configuration: {e}")
    
    def _load_ignore_lists(self):
        """Load ignore lists to filter out known/owned devices."""
        ignore_dir = self.config.get('paths', {}).get('ignore_lists_dir', './ignore_lists/')
        
        # Load MAC ignore list
        mac_file = os.path.join(ignore_dir, 'mac_list.json')
        if os.path.exists(mac_file):
            try:
                with open(mac_file, 'r') as f:
                    mac_list = json.load(f)
                    # Normalize MAC addresses to uppercase
                    self.ignored_macs = set(mac.upper() for mac in mac_list if mac)
                    logger.info(f"Loaded {len(self.ignored_macs)} ignored MACs from {mac_file}")
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"Could not load MAC ignore list: {e}")
        else:
            logger.info(f"No MAC ignore list found at {mac_file}")
        
        # Load SSID ignore list
        ssid_file = os.path.join(ignore_dir, 'ssid_list.json')
        if os.path.exists(ssid_file):
            try:
                with open(ssid_file, 'r') as f:
                    ssid_list = json.load(f)
                    self.ignored_ssids = set(ssid for ssid in ssid_list if ssid)
                    logger.info(f"Loaded {len(self.ignored_ssids)} ignored SSIDs from {ssid_file}")
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"Could not load SSID ignore list: {e}")
        else:
            logger.info(f"No SSID ignore list found at {ssid_file}")
    
    def is_ignored(self, identifier: str, identifier_type: str) -> bool:
        """Check if a device/network should be ignored."""
        if identifier_type == 'BSSID':
            return identifier.upper() in self.ignored_macs
        elif identifier_type in ('SSID', 'PROBE'):
            return identifier in self.ignored_ssids
        return False
    
    def is_common_ssid(self, ssid: str) -> bool:
        """Check if SSID is a common public/carrier network."""
        if not ssid:
            return False
        # Check exact match
        if ssid in COMMON_PUBLIC_SSIDS:
            return True
        # Check case-insensitive
        ssid_lower = ssid.lower()
        for common in COMMON_PUBLIC_SSIDS:
            if common.lower() == ssid_lower:
                return True
        return False
    
    @staticmethod
    def lookup_manufacturer(mac: str) -> str:
        """Look up manufacturer from MAC address OUI."""
        if not mac or len(mac) < 8:
            return "Unknown"
        
        # Normalize MAC format to XX:XX:XX
        mac_clean = mac.upper().replace('-', ':').replace('.', ':')
        oui = mac_clean[:8]  # First 3 bytes (8 chars with colons)
        
        return OUI_DATABASE.get(oui, "Unknown")
    
    def calculate_threat_score(self, device: WirelessDevice) -> float:
        """
        Calculate a threat score for a device based on multiple factors.
        Score range: 0.0 (low threat) to 1.0 (high threat)
        """
        score = 0.0
        
        # Factor 1: Number of stops (max 0.4)
        # More stops = higher threat
        num_stops = len(device.stops_seen)
        total_stops = len(self.stops)
        if total_stops > 0:
            stop_ratio = num_stops / total_stops
            score += stop_ratio * 0.4
        
        # Factor 2: Device type (max 0.2)
        # BSSIDs are more specific than SSIDs
        if device.identifier_type == 'BSSID':
            score += 0.2  # Most specific - actual device
        elif device.identifier_type == 'PROBE':
            score += 0.15  # Probe requests are somewhat unique
        elif device.identifier_type == 'SSID':
            score += 0.05  # SSIDs can be common
        
        # Factor 3: Common SSID penalty (reduce by 0.2)
        if device.identifier_type in ('SSID', 'PROBE'):
            if self.is_common_ssid(device.identifier):
                score -= 0.3  # Significant reduction for common networks
        
        # Factor 4: Signal strength pattern (max 0.2)
        # Strong signals at multiple locations = higher threat
        if device.signal_by_stop:
            avg_signal = sum(device.signal_by_stop.values()) / len(device.signal_by_stop)
            # Signal is negative dBm, closer to 0 = stronger
            if avg_signal > -50:  # Very strong
                score += 0.2
            elif avg_signal > -65:  # Strong
                score += 0.15
            elif avg_signal > -75:  # Medium
                score += 0.1
            else:  # Weak
                score += 0.05
        
        # Factor 5: Unknown manufacturer bonus (max 0.1)
        if device.identifier_type == 'BSSID':
            if device.manufacturer == "Unknown":
                score += 0.1  # Unknown devices are more suspicious
        
        # Factor 6: Time correlation (max 0.1)
        # If timestamps are close together at different stops, more suspicious
        if len(device.timestamps_by_stop) >= 2:
            # Check if device was seen at different stops within same day
            all_dates = set()
            for stop_name, timestamps in device.timestamps_by_stop.items():
                for ts in timestamps:
                    if isinstance(ts, datetime):
                        all_dates.add(ts.date())
            
            # Same day sightings at multiple stops = suspicious
            if len(all_dates) <= 2 and num_stops >= 2:
                score += 0.1
        
        # Clamp score between 0 and 1
        return max(0.0, min(1.0, score))
    
    @staticmethod
    def haversine_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
        """
        Calculate the great-circle distance between two points on Earth.
        Returns distance in meters.
        """
        R = 6371000  # Earth's radius in meters
        
        lat1, lon1, lat2, lon2 = map(radians, [lat1, lon1, lat2, lon2])
        
        dlat = lat2 - lat1
        dlon = lon2 - lon1
        
        a = sin(dlat/2)**2 + cos(lat1) * cos(lat2) * sin(dlon/2)**2
        c = 2 * atan2(sqrt(a), sqrt(1-a))
        
        return R * c
    
    def find_nearest_stop(self, latitude: float, longitude: float) -> Optional[Stop]:
        """Find the nearest configured stop to a given coordinate within radius."""
        nearest_stop = None
        min_distance = float('inf')
        
        for stop in self.stops:
            distance = self.haversine_distance(
                latitude, longitude,
                stop.latitude, stop.longitude
            )
            
            if distance <= self.radius_meters and distance < min_distance:
                min_distance = distance
                nearest_stop = stop
        
        return nearest_stop
    
    def analyze_kismet_database(self, db_path: str) -> int:
        """
        Analyze a Kismet database for wireless devices near configured stops.
        Returns count of devices processed.
        """
        if not os.path.exists(db_path):
            logger.error(f"Database not found: {db_path}")
            return 0
        
        count = 0
        
        try:
            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            
            # Query devices with GPS coordinates
            cursor.execute("""
                SELECT 
                    devmac,
                    type,
                    device,
                    avg_lat,
                    avg_lon,
                    first_time,
                    last_time,
                    strongest_signal
                FROM devices
                WHERE avg_lat IS NOT NULL 
                AND avg_lon IS NOT NULL
                AND avg_lat != 0 
                AND avg_lon != 0
            """)
            
            devices = cursor.fetchall()
            
            for device in devices:
                try:
                    mac = device[0]
                    dev_type = device[1]
                    device_json = device[2]
                    lat = device[3]
                    lon = device[4]
                    first_time = device[5]
                    last_time = device[6]
                    signal = device[7]
                    
                    if lat and lon:
                        stop = self.find_nearest_stop(lat, lon)
                        if stop:
                            # Parse timestamps
                            try:
                                first_dt = datetime.fromtimestamp(first_time) if first_time else None
                                last_dt = datetime.fromtimestamp(last_time) if last_time else None
                            except:
                                first_dt = None
                                last_dt = None
                            
                            # Track BSSID
                            if mac:
                                self.bssids_by_stop[stop.name].add(mac)
                                device_key = f"BSSID:{mac}"
                                if device_key not in self.devices:
                                    self.devices[device_key] = WirelessDevice(
                                        identifier=mac,
                                        identifier_type='BSSID',
                                        manufacturer=self.lookup_manufacturer(mac)
                                    )
                                dev = self.devices[device_key]
                                dev.stops_seen.add(stop.name)
                                
                                # Track signal by stop (keep strongest)
                                if signal:
                                    if stop.name not in dev.signal_by_stop or signal > dev.signal_by_stop[stop.name]:
                                        dev.signal_by_stop[stop.name] = signal
                                    dev.signal_strength = signal
                                
                                # Track timestamps by stop
                                if stop.name not in dev.timestamps_by_stop:
                                    dev.timestamps_by_stop[stop.name] = []
                                if first_dt:
                                    dev.timestamps_by_stop[stop.name].append(first_dt)
                                if last_dt and last_dt != first_dt:
                                    dev.timestamps_by_stop[stop.name].append(last_dt)
                                
                                # Update first/last seen
                                if first_dt:
                                    if dev.first_seen is None or first_dt < dev.first_seen:
                                        dev.first_seen = first_dt
                                if last_dt:
                                    if dev.last_seen is None or last_dt > dev.last_seen:
                                        dev.last_seen = last_dt
                            
                            # Extract SSIDs from device JSON
                            if device_json:
                                try:
                                    data = json.loads(device_json)
                                    dot11 = data.get('dot11.device', {})
                                    
                                    # Get probed SSIDs
                                    probe_record = dot11.get('dot11.device.last_probed_ssid_record', {})
                                    probed_ssid = probe_record.get('dot11.probedssid.ssid')
                                    if probed_ssid:
                                        self.probes_by_stop[stop.name].add(probed_ssid)
                                        device_key = f"PROBE:{probed_ssid}"
                                        if device_key not in self.devices:
                                            self.devices[device_key] = WirelessDevice(
                                                identifier=probed_ssid,
                                                identifier_type='PROBE'
                                            )
                                        dev = self.devices[device_key]
                                        dev.stops_seen.add(stop.name)
                                        if stop.name not in dev.timestamps_by_stop:
                                            dev.timestamps_by_stop[stop.name] = []
                                        if first_dt:
                                            dev.timestamps_by_stop[stop.name].append(first_dt)
                                    
                                    # Get advertised SSID (if AP)
                                    advertised = dot11.get('dot11.device.last_beaconed_ssid_record', {})
                                    adv_ssid = advertised.get('dot11.advertisedssid.ssid')
                                    if adv_ssid:
                                        self.ssids_by_stop[stop.name].add(adv_ssid)
                                        device_key = f"SSID:{adv_ssid}"
                                        if device_key not in self.devices:
                                            self.devices[device_key] = WirelessDevice(
                                                identifier=adv_ssid,
                                                identifier_type='SSID'
                                            )
                                        dev = self.devices[device_key]
                                        dev.stops_seen.add(stop.name)
                                        if stop.name not in dev.timestamps_by_stop:
                                            dev.timestamps_by_stop[stop.name] = []
                                        if first_dt:
                                            dev.timestamps_by_stop[stop.name].append(first_dt)
                                        
                                except (json.JSONDecodeError, KeyError):
                                    pass
                            
                            count += 1
                
                except Exception as e:
                    logger.debug(f"Error processing device: {e}")
                    continue
            
            conn.close()
            logger.info(f"Analyzed {count} devices from: {db_path}")
            
        except sqlite3.Error as e:
            logger.error(f"Database error: {e}")
        
        return count
    
    def analyze_cyt_logs(self, log_directory: str) -> int:
        """
        Analyze CYT log files for probe requests and wireless devices.
        Returns count of entries processed.
        """
        log_pattern = os.path.join(log_directory, "cyt_log_*")
        log_files = glob.glob(log_pattern)
        count = 0
        
        import re
        mac_pattern = re.compile(r'([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})')
        
        for log_file in log_files:
            try:
                with open(log_file, 'r') as f:
                    for line in f:
                        # Look for MAC addresses
                        macs = mac_pattern.findall(line)
                        
                        # Look for GPS coordinates
                        if 'GPS' in line or 'lat' in line.lower():
                            gps_match = re.search(r'([+-]?\d+\.?\d*)[,\s]+([+-]?\d+\.?\d*)', line)
                            if gps_match and macs:
                                try:
                                    lat = float(gps_match.group(1))
                                    lon = float(gps_match.group(2))
                                    
                                    # Validate coordinates are reasonable
                                    if -90 <= lat <= 90 and -180 <= lon <= 180:
                                        stop = self.find_nearest_stop(lat, lon)
                                        if stop:
                                            for mac_tuple in macs:
                                                mac = ':'.join(mac_tuple).upper()
                                                self.bssids_by_stop[stop.name].add(mac)
                                                device_key = f"BSSID:{mac}"
                                                if device_key not in self.devices:
                                                    self.devices[device_key] = WirelessDevice(
                                                        identifier=mac,
                                                        identifier_type='BSSID'
                                                    )
                                                self.devices[device_key].stops_seen.add(stop.name)
                                                count += 1
                                except ValueError:
                                    pass
                                    
            except Exception as e:
                logger.debug(f"Error reading log file {log_file}: {e}")
        
        logger.info(f"Analyzed {count} entries from CYT logs")
        return count
    
    def add_manual_observation(
        self,
        identifier: str,
        identifier_type: str,
        stop_name: str
    ) -> bool:
        """Manually add an observation of a wireless device at a stop."""
        valid_stops = {s.name for s in self.stops}
        if stop_name not in valid_stops:
            logger.warning(f"Unknown stop: {stop_name}")
            return False
        
        if identifier_type == 'BSSID':
            self.bssids_by_stop[stop_name].add(identifier)
        elif identifier_type == 'SSID':
            self.ssids_by_stop[stop_name].add(identifier)
        elif identifier_type == 'PROBE':
            self.probes_by_stop[stop_name].add(identifier)
        else:
            logger.warning(f"Unknown identifier type: {identifier_type}")
            return False
        
        device_key = f"{identifier_type}:{identifier}"
        if device_key not in self.devices:
            self.devices[device_key] = WirelessDevice(
                identifier=identifier,
                identifier_type=identifier_type
            )
        self.devices[device_key].stops_seen.add(stop_name)
        return True
    
    def find_multi_stop_devices(self) -> Dict[str, List[WirelessDevice]]:
        """Find devices that appear at multiple stops (excluding ignored devices)."""
        results = {
            'bssids': [],
            'ssids': [],
            'probes': []
        }
        
        ignored_count = 0
        common_ssid_count = 0
        
        for device_key, device in self.devices.items():
            # Skip ignored devices
            if self.is_ignored(device.identifier, device.identifier_type):
                ignored_count += 1
                continue
            
            if len(device.stops_seen) >= self.minimum_occurrences:
                # Calculate threat score for this device
                device.threat_score = self.calculate_threat_score(device)
                
                # Flag common SSIDs but still include them (with low threat score)
                if device.identifier_type in ('SSID', 'PROBE'):
                    if self.is_common_ssid(device.identifier):
                        common_ssid_count += 1
                
                if device.identifier_type == 'BSSID':
                    results['bssids'].append(device)
                elif device.identifier_type == 'SSID':
                    results['ssids'].append(device)
                elif device.identifier_type == 'PROBE':
                    results['probes'].append(device)
        
        if ignored_count > 0:
            logger.info(f"Filtered out {ignored_count} ignored devices from results")
        if common_ssid_count > 0:
            logger.info(f"Found {common_ssid_count} common public SSIDs (scored lower)")
        
        # Sort by threat score (descending), then by number of stops
        for key in results:
            results[key].sort(key=lambda d: (d.threat_score, len(d.stops_seen)), reverse=True)
        
        return results
    
    def generate_report(self, output_path: Optional[str] = None) -> str:
        """Generate a text comparison report."""
        multi_stop_devices = self.find_multi_stop_devices()
        
        # Ignore list status
        ignore_status = []
        if self.ignored_macs:
            ignore_status.append(f"{len(self.ignored_macs)} MACs")
        if self.ignored_ssids:
            ignore_status.append(f"{len(self.ignored_ssids)} SSIDs")
        ignore_str = f"Filtering: {', '.join(ignore_status)}" if ignore_status else "Filtering: None (no ignore lists loaded)"
        
        report_lines = [
            "=" * 80,
            "STOP COMPARISON REPORT - Chasing Your Tail NG",
            "=" * 80,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"Minimum occurrences threshold: {self.minimum_occurrences}",
            f"Search radius: {self.radius_meters} meters",
            f"{ignore_str}",
            "",
            "-" * 80,
            "CONFIGURED STOPS",
            "-" * 80,
        ]
        
        for i, stop in enumerate(self.stops, 1):
            report_lines.append(
                f"  {i}. {stop.name}: ({stop.latitude:.6f}, {stop.longitude:.6f})"
            )
            if stop.description:
                report_lines.append(f"     Description: {stop.description}")
        
        report_lines.extend([
            "",
            "-" * 80,
            "DATA SUMMARY BY STOP",
            "-" * 80,
        ])
        
        for stop in self.stops:
            report_lines.append(f"\n  {stop.name}:")
            report_lines.append(f"    BSSIDs: {len(self.bssids_by_stop[stop.name])}")
            report_lines.append(f"    SSIDs: {len(self.ssids_by_stop[stop.name])}")
            report_lines.append(f"    Probes: {len(self.probes_by_stop[stop.name])}")
        
        report_lines.extend([
            "",
            "=" * 80,
            "⚠️  DEVICES APPEARING AT MULTIPLE STOPS (POTENTIAL SURVEILLANCE)",
            "=" * 80,
        ])
        
        total_suspicious = (
            len(multi_stop_devices['bssids']) +
            len(multi_stop_devices['ssids']) +
            len(multi_stop_devices['probes'])
        )
        
        if total_suspicious == 0:
            report_lines.append("\n  ✓ No devices found at multiple stops.")
        else:
            report_lines.append(f"\n  ⚠️  FOUND {total_suspicious} SUSPICIOUS ITEMS\n")
            
            if multi_stop_devices['bssids']:
                report_lines.extend([
                    "-" * 80,
                    f"BSSIDs SEEN AT {self.minimum_occurrences}+ STOPS ({len(multi_stop_devices['bssids'])} found)",
                    "-" * 80,
                ])
                for device in multi_stop_devices['bssids']:
                    stops_str = ", ".join(sorted(device.stops_seen))
                    report_lines.append(
                        f"  • {device.identifier} - Seen at {len(device.stops_seen)} stops: [{stops_str}]"
                    )
            
            if multi_stop_devices['ssids']:
                report_lines.extend([
                    "",
                    "-" * 80,
                    f"SSIDs SEEN AT {self.minimum_occurrences}+ STOPS ({len(multi_stop_devices['ssids'])} found)",
                    "-" * 80,
                ])
                for device in multi_stop_devices['ssids']:
                    stops_str = ", ".join(sorted(device.stops_seen))
                    report_lines.append(
                        f"  • \"{device.identifier}\" - Seen at {len(device.stops_seen)} stops: [{stops_str}]"
                    )
            
            if multi_stop_devices['probes']:
                report_lines.extend([
                    "",
                    "-" * 80,
                    f"PROBE REQUESTS SEEN AT {self.minimum_occurrences}+ STOPS ({len(multi_stop_devices['probes'])} found)",
                    "-" * 80,
                ])
                for device in multi_stop_devices['probes']:
                    stops_str = ", ".join(sorted(device.stops_seen))
                    report_lines.append(
                        f"  • \"{device.identifier}\" - Seen at {len(device.stops_seen)} stops: [{stops_str}]"
                    )
        
        report_lines.extend([
            "",
            "=" * 80,
            "ANALYSIS SUMMARY",
            "=" * 80,
            f"  Total stops configured: {len(self.stops)}",
            f"  Total unique BSSIDs: {len(set().union(*self.bssids_by_stop.values()) if self.bssids_by_stop else set())}",
            f"  Total unique SSIDs: {len(set().union(*self.ssids_by_stop.values()) if self.ssids_by_stop else set())}",
            f"  Total unique Probes: {len(set().union(*self.probes_by_stop.values()) if self.probes_by_stop else set())}",
            f"  Suspicious BSSIDs: {len(multi_stop_devices['bssids'])}",
            f"  Suspicious SSIDs: {len(multi_stop_devices['ssids'])}",
            f"  Suspicious Probes: {len(multi_stop_devices['probes'])}",
            "",
            "=" * 80,
        ])
        
        report_content = "\n".join(report_lines)
        
        if output_path:
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(report_content)
            logger.info(f"Report saved to: {output_path}")
        
        return report_content
    
    def generate_html_report(self, output_path: Optional[str] = None) -> str:
        """Generate an HTML version of the comparison report."""
        multi_stop_devices = self.find_multi_stop_devices()
        
        total_suspicious = (
            len(multi_stop_devices['bssids']) +
            len(multi_stop_devices['ssids']) +
            len(multi_stop_devices['probes'])
        )
        
        # Calculate totals safely
        total_bssids = len(set().union(*self.bssids_by_stop.values())) if self.bssids_by_stop else 0
        total_ssids = len(set().union(*self.ssids_by_stop.values())) if self.ssids_by_stop else 0
        total_probes = len(set().union(*self.probes_by_stop.values())) if self.probes_by_stop else 0
        
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Stop Comparison Report - Chasing Your Tail NG</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #1a1a1a;
            color: #eee;
        }}
        h1 {{
            color: #00ff41;
            border-bottom: 2px solid #00ff41;
            padding-bottom: 10px;
        }}
        h2 {{ color: #ff6b35; margin-top: 30px; }}
        h3 {{ color: #00d4ff; }}
        .summary-box {{
            background: #2a2a2a;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            border-left: 4px solid #00ff41;
        }}
        .warning-box {{
            background: #3d1f1f;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            border-left: 4px solid #ff6b35;
        }}
        .success-box {{
            background: #1f3d1f;
            border-radius: 10px;
            padding: 20px;
            margin: 20px 0;
            border-left: 4px solid #28a745;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 15px 0;
            background: #2a2a2a;
            border-radius: 8px;
            overflow: hidden;
        }}
        th, td {{
            padding: 12px 15px;
            text-align: left;
            border-bottom: 1px solid #3a3a3a;
        }}
        th {{
            background: #333;
            color: #00ff41;
            font-weight: 600;
        }}
        tr:hover {{ background: #333; }}
        .stop-badge {{
            display: inline-block;
            background: #333;
            color: #00d4ff;
            padding: 3px 8px;
            border-radius: 4px;
            margin: 2px;
            font-size: 0.85em;
        }}
        .alert-count {{
            font-size: 3em;
            font-weight: bold;
            color: #ff6b35;
        }}
        .stat-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }}
        .stat-card {{
            background: #2a2a2a;
            border-radius: 8px;
            padding: 15px;
            text-align: center;
        }}
        .stat-number {{
            font-size: 2em;
            font-weight: bold;
            color: #00ff41;
        }}
        .stat-label {{ color: #888; font-size: 0.9em; }}
        code {{ background: #333; padding: 2px 6px; border-radius: 3px; }}
    </style>
</head>
<body>
    <h1>🔍 Stop Comparison Report</h1>
    <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
    
    <div class="summary-box">
        <h2>📍 Configured Stops</h2>
        <table>
            <tr><th>#</th><th>Name</th><th>Coordinates</th><th>Description</th></tr>
"""
        
        for i, stop in enumerate(self.stops, 1):
            html += f"""            <tr>
                <td>{i}</td>
                <td>{stop.name}</td>
                <td>{stop.latitude:.6f}, {stop.longitude:.6f}</td>
                <td>{stop.description or '-'}</td>
            </tr>
"""
        
        html += f"""        </table>
        <p><strong>Search Radius:</strong> {self.radius_meters}m | <strong>Min Occurrences:</strong> {self.minimum_occurrences}</p>
        <p><strong>🛡️ Ignore Lists:</strong> {len(self.ignored_macs)} MACs, {len(self.ignored_ssids)} SSIDs filtered out</p>
    </div>
    
    <div class="stat-grid">
        <div class="stat-card">
            <div class="stat-number">{len(self.stops)}</div>
            <div class="stat-label">Stops</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{total_bssids}</div>
            <div class="stat-label">Unique BSSIDs</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{total_ssids}</div>
            <div class="stat-label">Unique SSIDs</div>
        </div>
        <div class="stat-card">
            <div class="stat-number">{total_probes}</div>
            <div class="stat-label">Unique Probes</div>
        </div>
    </div>
"""
        
        if total_suspicious == 0:
            html += """    <div class="success-box">
        <h2>✅ No Suspicious Devices Found</h2>
        <p>No devices were detected at multiple stops.</p>
    </div>
"""
        else:
            html += f"""    <div class="warning-box">
        <h2>⚠️ Potential Surveillance Detected</h2>
        <p class="alert-count">{total_suspicious}</p>
        <p>Devices found at {self.minimum_occurrences} or more stops</p>
    </div>
"""
            
            for category, label, icon in [
                ('bssids', 'BSSIDs', '📡'),
                ('ssids', 'SSIDs', '📶'),
                ('probes', 'Probe Requests', '📨')
            ]:
                if multi_stop_devices[category]:
                    html += f"""    <h3>{icon} {label} at Multiple Stops ({len(multi_stop_devices[category])} found)</h3>
    <table>
        <tr>
            <th>Threat</th>
            <th>Identifier</th>
            {'<th>Manufacturer</th>' if category == 'bssids' else ''}
            <th>Stops</th>
            <th>Signal</th>
            <th>First Seen</th>
            <th>Locations</th>
        </tr>
"""
                    for device in multi_stop_devices[category]:
                        stops_badges = " ".join(
                            f'<span class="stop-badge">{s}</span>'
                            for s in sorted(device.stops_seen)
                        )
                        identifier_display = f'<code>{device.identifier}</code>' if category == 'bssids' else f'"{device.identifier}"'
                        
                        # Threat score color
                        threat_pct = int(device.threat_score * 100)
                        if device.threat_score >= 0.7:
                            threat_color = '#ff4444'  # Red - high threat
                            threat_label = 'HIGH'
                        elif device.threat_score >= 0.4:
                            threat_color = '#ffaa00'  # Orange - medium
                            threat_label = 'MED'
                        else:
                            threat_color = '#44aa44'  # Green - low
                            threat_label = 'LOW'
                        
                        # Signal strength display
                        if device.signal_by_stop:
                            avg_signal = sum(device.signal_by_stop.values()) // len(device.signal_by_stop)
                            signal_display = f'{avg_signal} dBm'
                        elif device.signal_strength:
                            signal_display = f'{device.signal_strength} dBm'
                        else:
                            signal_display = '-'
                        
                        # Timestamp display
                        if device.first_seen:
                            time_display = device.first_seen.strftime('%m/%d %H:%M')
                        elif device.timestamps_by_stop:
                            # Get earliest timestamp from any stop
                            all_times = []
                            for times in device.timestamps_by_stop.values():
                                all_times.extend(times)
                            if all_times:
                                earliest = min(all_times)
                                time_display = earliest.strftime('%m/%d %H:%M')
                            else:
                                time_display = '-'
                        else:
                            time_display = '-'
                        
                        # Manufacturer column (only for BSSIDs)
                        manufacturer_col = f'<td>{device.manufacturer}</td>' if category == 'bssids' else ''
                        
                        # Common SSID indicator
                        if category in ('ssids', 'probes') and self.is_common_ssid(device.identifier):
                            identifier_display += ' <span style="color:#888;font-size:0.8em">(common)</span>'
                        
                        html += f"""        <tr>
            <td><span style="color:{threat_color};font-weight:bold">{threat_label}</span> <span style="color:#888;font-size:0.8em">({threat_pct}%)</span></td>
            <td>{identifier_display}</td>
            {manufacturer_col}
            <td>{len(device.stops_seen)}</td>
            <td>{signal_display}</td>
            <td>{time_display}</td>
            <td>{stops_badges}</td>
        </tr>
"""
                    html += """    </table>
"""
        
        html += """    <div class="summary-box">
        <h2>📋 Analysis Notes</h2>
        <p>Devices at multiple stops may indicate:</p>
        <ul>
            <li><strong>Surveillance</strong> - Mobile hotspots following your route</li>
            <li><strong>Personal devices</strong> - Your own devices (add to ignore list)</li>
            <li><strong>Common networks</strong> - Carrier hotspots, chain store WiFi</li>
        </ul>
    </div>
    
    <footer style="text-align: center; margin-top: 40px; color: #666; border-top: 1px solid #333; padding-top: 20px;">
        <p>Chasing Your Tail NG - Stop Comparison Feature</p>
    </footer>
</body>
</html>"""
        
        if output_path:
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            with open(output_path, 'w') as f:
                f.write(html)
            logger.info(f"HTML report saved to: {output_path}")
        
        return html
    
    def run_analysis(self) -> Dict[str, Any]:
        """Run full analysis using configured data sources."""
        print("🔍 Starting Stop Comparison Analysis...")
        print("=" * 50)
        
        # Get Kismet database path from config
        kismet_pattern = self.config.get('paths', {}).get('kismet_logs', '')
        
        if kismet_pattern:
            db_files = glob.glob(kismet_pattern)
            if db_files:
                print(f"📊 Found {len(db_files)} Kismet database(s)")
                for db_path in db_files:
                    count = self.analyze_kismet_database(db_path)
                    print(f"   📁 {os.path.basename(db_path)}: {count} devices near stops")
            else:
                print(f"⚠️ No Kismet databases found at: {kismet_pattern}")
        
        # Analyze CYT logs
        log_dir = self.config.get('paths', {}).get('log_dir', './logs/')
        if os.path.isdir(log_dir):
            count = self.analyze_cyt_logs(log_dir)
            print(f"📋 Analyzed CYT logs: {count} entries")
        
        # Get results
        multi_stop_devices = self.find_multi_stop_devices()
        
        total_suspicious = (
            len(multi_stop_devices['bssids']) +
            len(multi_stop_devices['ssids']) +
            len(multi_stop_devices['probes'])
        )
        
        print(f"\n{'='*50}")
        if total_suspicious > 0:
            print(f"⚠️  FOUND {total_suspicious} DEVICES AT MULTIPLE STOPS!")
        else:
            print("✅ No devices found at multiple stops")
        
        return {
            'stops': [{'name': s.name, 'lat': s.latitude, 'lon': s.longitude} for s in self.stops],
            'suspicious_bssids': [{'id': d.identifier, 'stops': list(d.stops_seen)} for d in multi_stop_devices['bssids']],
            'suspicious_ssids': [{'id': d.identifier, 'stops': list(d.stops_seen)} for d in multi_stop_devices['ssids']],
            'suspicious_probes': [{'id': d.identifier, 'stops': list(d.stops_seen)} for d in multi_stop_devices['probes']],
            'total_suspicious': total_suspicious
        }


def main():
    """Main entry point for command-line usage."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Compare wireless devices across multiple predetermined stops'
    )
    parser.add_argument('--config', '-c', default='config.json', help='Config file path')
    parser.add_argument('--output', '-o', help='Output directory for reports')
    parser.add_argument('--format', '-f', choices=['text', 'html', 'both'], default='both')
    parser.add_argument('--demo', action='store_true', help='Run with demo data')
    
    args = parser.parse_args()
    
    try:
        analyzer = StopComparisonAnalyzer(args.config)
    except FileNotFoundError:
        print("❌ Config file not found. Please create config.json with stop_comparison section.")
        return 1
    
    if not analyzer.stops:
        print("❌ No stops configured. Add stops to config.json under 'stop_comparison.stops'")
        return 1
    
    if args.demo:
        # Add demo data
        demo_data = [
            ('AA:BB:CC:DD:EE:01', 'BSSID', analyzer.stops[0].name),
            ('AA:BB:CC:DD:EE:01', 'BSSID', analyzer.stops[1].name if len(analyzer.stops) > 1 else analyzer.stops[0].name),
            ('AA:BB:CC:DD:EE:02', 'BSSID', analyzer.stops[0].name),
            ('SuspiciousNetwork', 'SSID', analyzer.stops[0].name),
            ('SuspiciousNetwork', 'SSID', analyzer.stops[1].name if len(analyzer.stops) > 1 else analyzer.stops[0].name),
            ('FollowerProbe', 'PROBE', analyzer.stops[0].name),
        ]
        if len(analyzer.stops) > 1:
            demo_data.append(('AA:BB:CC:DD:EE:01', 'BSSID', analyzer.stops[1].name))
            demo_data.append(('FollowerProbe', 'PROBE', analyzer.stops[1].name))
        if len(analyzer.stops) > 2:
            demo_data.append(('AA:BB:CC:DD:EE:01', 'BSSID', analyzer.stops[2].name))
            demo_data.append(('FollowerProbe', 'PROBE', analyzer.stops[2].name))
        
        for identifier, id_type, stop in demo_data:
            analyzer.add_manual_observation(identifier, id_type, stop)
        print("📋 Demo data loaded")
    else:
        analyzer.run_analysis()
    
    # Generate reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_dir = args.output or './surveillance_reports/'
    pathlib.Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    if args.format in ('text', 'both'):
        text_path = os.path.join(output_dir, f'stop_comparison_{timestamp}.txt')
        report = analyzer.generate_report(text_path)
        print(report)
    
    if args.format in ('html', 'both'):
        html_path = os.path.join(output_dir, f'stop_comparison_{timestamp}.html')
        analyzer.generate_html_report(html_path)
        print(f"\n📄 HTML report: {html_path}")
    
    return 0


if __name__ == '__main__':
    exit(main())
