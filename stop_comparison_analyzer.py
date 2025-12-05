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
    
    def __hash__(self):
        return hash((self.identifier, self.identifier_type))


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
                            # Track BSSID
                            if mac:
                                self.bssids_by_stop[stop.name].add(mac)
                                device_key = f"BSSID:{mac}"
                                if device_key not in self.devices:
                                    self.devices[device_key] = WirelessDevice(
                                        identifier=mac,
                                        identifier_type='BSSID'
                                    )
                                self.devices[device_key].stops_seen.add(stop.name)
                                if signal:
                                    self.devices[device_key].signal_strength = signal
                            
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
                                        self.devices[device_key].stops_seen.add(stop.name)
                                    
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
                                        self.devices[device_key].stops_seen.add(stop.name)
                                        
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
        
        for device_key, device in self.devices.items():
            # Skip ignored devices
            if self.is_ignored(device.identifier, device.identifier_type):
                ignored_count += 1
                continue
            
            if len(device.stops_seen) >= self.minimum_occurrences:
                if device.identifier_type == 'BSSID':
                    results['bssids'].append(device)
                elif device.identifier_type == 'SSID':
                    results['ssids'].append(device)
                elif device.identifier_type == 'PROBE':
                    results['probes'].append(device)
        
        if ignored_count > 0:
            logger.info(f"Filtered out {ignored_count} ignored devices from results")
        
        # Sort by number of stops seen (descending)
        for key in results:
            results[key].sort(key=lambda d: len(d.stops_seen), reverse=True)
        
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
        <tr><th>Identifier</th><th>Stops</th><th>Locations</th></tr>
"""
                    for device in multi_stop_devices[category]:
                        stops_badges = " ".join(
                            f'<span class="stop-badge">{s}</span>'
                            for s in sorted(device.stops_seen)
                        )
                        identifier_display = f'<code>{device.identifier}</code>' if category == 'bssids' else f'"{device.identifier}"'
                        html += f"""        <tr>
            <td>{identifier_display}</td>
            <td>{len(device.stops_seen)}</td>
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
