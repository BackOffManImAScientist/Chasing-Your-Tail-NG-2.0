# Chasing Your Tail (CYT)

A comprehensive Wi-Fi probe request analyzer that monitors and tracks wireless devices by analyzing their probe requests. The system integrates with Kismet for packet capture and WiGLE API for SSID geolocation analysis, featuring advanced surveillance detection capabilities.

## 🚨 Security Notice

This project has been security-hardened to eliminate critical vulnerabilities:
- **SQL injection prevention** with parameterized queries
- **Encrypted credential management** for API keys
- **Input validation** and sanitization
- **Secure ignore list loading** (no more `exec()` calls)

**⚠️ REQUIRED: Run `python3 migrate_credentials.py` before first use to secure your API keys!**

## Features

- **Real-time Wi-Fi monitoring** with Kismet integration
- **Advanced surveillance detection** with persistence scoring
- **🆕 Automatic GPS integration** - extracts coordinates from Bluetooth GPS via Kismet
- **🆕 Stop Comparison Analysis** - Compare BSSIDs, SSIDs, and Probe Requests across multiple predetermined locations
- **GPS correlation** and location clustering (100m threshold)
- **Spectacular KML visualization** for Google Earth with professional styling and interactive content
- **Multi-format reporting** - Markdown, HTML (with pandoc), and KML outputs
- **Time-window tracking** (5, 10, 15, 20 minute windows)
- **WiGLE API integration** for SSID geolocation
- **Multi-location tracking algorithms** for detecting following behavior
- **Enhanced GUI interface** with surveillance analysis and stop comparison buttons
- **Organized file structure** with dedicated output directories
- **Comprehensive logging** and analysis tools

## Requirements

- Python 3.6+
- Kismet wireless packet capture
- Wi-Fi adapter supporting monitor mode
- Linux-based system
- WiGLE API key (optional)

## Installation & Setup

### 1. Install Dependencies
```bash
pip3 install -r requirements.txt
```

### 2. Security Setup (REQUIRED FIRST TIME)
```bash
# Migrate credentials from insecure config.json
python3 migrate_credentials.py

# Verify security hardening
python3 chasing_your_tail.py
# Should show: "🔒 SECURE MODE: All SQL injection vulnerabilities have been eliminated!"
```

### 3. Configure System
Edit `config.json` with your paths and settings:
- Kismet database path pattern
- Log and ignore list directories
- Time window configurations
- Geographic search boundaries
- Stop comparison locations (see below)

## Usage

### GUI Interface
```bash
python3 cyt_gui.py  # Enhanced GUI with surveillance analysis
```

**GUI Features:**
- 📊 **Check System Status** - Verify Kismet and database connectivity
- 📝 **Create Ignore Lists** - Generate ignore lists from current Kismet data
- 🗑️ **Delete Ignore Lists** - Remove existing ignore lists
- 🚀 **START CHASING YOUR TAIL** - Begin real-time monitoring
- 📈 **Analyze Logs** - Historical probe request analysis
- 🗺️ **Surveillance Analysis** - GPS-correlated persistence detection with KML visualization
- 📍 **Stop Comparison** - Compare devices across predetermined locations
- ⚙️ **Configure Stops** - GUI to set up comparison stop locations

### Command Line Monitoring
```bash
# Start core monitoring (secure)
python3 chasing_your_tail.py

# Start Kismet (ONLY working script - July 23, 2025 fix)
./start_kismet_clean.sh
```

### Data Analysis
```bash
# Analyze collected probe data (past 14 days, local only - default)
python3 probe_analyzer.py

# Analyze past 7 days only
python3 probe_analyzer.py --days 7

# Analyze ALL logs (may be slow for large datasets)
python3 probe_analyzer.py --all-logs

# Analyze WITH WiGLE API calls (consumes API credits!)
python3 probe_analyzer.py --wigle
```

### Surveillance Detection & Advanced Visualization
```bash
# Automatic GPS extraction with spectacular KML visualization
python3 surveillance_analyzer.py

# Run analysis with demo GPS data (for testing - uses Phoenix coordinates)
python3 surveillance_analyzer.py --demo

# Analyze specific Kismet database
python3 surveillance_analyzer.py --kismet-db /path/to/kismet.db

# Focus on stalking detection with high persistence threshold
python3 surveillance_analyzer.py --stalking-only --min-persistence 0.8

# Export results to JSON for further analysis
python3 surveillance_analyzer.py --output-json analysis_results.json

# Analyze with external GPS data from JSON file
python3 surveillance_analyzer.py --gps-file gps_coordinates.json
```

---

## 🆕 Stop Comparison Feature

The Stop Comparison feature allows you to define 2-5 predetermined GPS locations (stops) and identify any BSSIDs, SSIDs, or Probe Requests that appear at multiple locations. This is useful for detecting if the same device is following you across different places.

### How It Works

1. **Define your stops** - Set 2-5 GPS coordinates for places you regularly visit (home, work, coffee shop, etc.)
2. **Collect data** - Run Kismet at each location to capture wireless data
3. **Run comparison** - Click "Stop Comparison" to analyze which devices appeared at multiple stops
4. **Review report** - Get a detailed report showing suspicious devices that followed you

### Configuring Stops via GUI

1. Click **⚙️ Configure Stops** in the GUI
2. Select the number of stops (2-5)
3. For each stop, enter:
   - **Name** - A friendly name (e.g., "Home", "Office")
   - **Latitude** - GPS latitude in decimal format (e.g., 33.4484)
   - **Longitude** - GPS longitude in decimal format (e.g., -112.0740)
   - **Description** - Optional notes
4. Click **💾 Save Configuration**

**💡 Tip:** Get coordinates from Google Maps by right-clicking any location and selecting the coordinates.

### Configuring Stops via config.json

Add the `stop_comparison` section to your `config.json`:

```json
{
  "paths": {
    "kismet_logs": "/path/to/kismet/*.kismet",
    "log_dir": "logs"
  },
  "stop_comparison": {
    "enabled": true,
    "radius_meters": 100,
    "minimum_occurrences": 2,
    "stops": [
      {
        "name": "Home",
        "latitude": 33.4484,
        "longitude": -112.0740,
        "description": "Starting location"
      },
      {
        "name": "Coffee Shop",
        "latitude": 33.4500,
        "longitude": -112.0760,
        "description": "Morning stop"
      },
      {
        "name": "Office",
        "latitude": 33.4520,
        "longitude": -112.0800,
        "description": "Work destination"
      }
    ]
  }
}
```

### Stop Comparison Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `enabled` | Enable/disable the feature | `true` |
| `radius_meters` | How close a device must be to a stop to count | `100` |
| `minimum_occurrences` | Minimum stops a device must appear at to be flagged | `2` |
| `stops` | Array of 2-5 stop locations | `[]` |

### Running Stop Comparison

**Via GUI:**
1. Click **📍 Stop Comparison** button
2. Wait for analysis to complete
3. View results in the Output Log
4. Optionally open the HTML report in your browser

**Via Command Line:**
```bash
# Run stop comparison analysis
python3 stop_comparison_analyzer.py

# Run with demo data (for testing)
python3 stop_comparison_analyzer.py --demo

# Generate only text report
python3 stop_comparison_analyzer.py --format text

# Generate only HTML report
python3 stop_comparison_analyzer.py --format html
```

### Understanding the Report

The Stop Comparison report shows:

- **Configured Stops** - Your defined locations
- **Data Summary** - How many BSSIDs, SSIDs, and Probes were found at each stop
- **Suspicious Devices** - Devices that appeared at 2+ stops, including:
  - **BSSIDs** - MAC addresses of access points/devices
  - **SSIDs** - Network names being broadcast
  - **Probe Requests** - Networks that devices are searching for

**⚠️ Devices at multiple stops may indicate:**
- Surveillance vehicles with mobile hotspots
- Your own devices (add to ignore list)
- Common networks (carrier hotspots, chain store WiFi)

---

### Ignore List Management
```bash
# Create new ignore lists from current Kismet data
python3 legacy/create_ignore_list.py  # Moved to legacy folder
```
**Note**: Ignore lists are now stored as JSON files in `./ignore_lists/`

## Core Components

- **chasing_your_tail.py**: Core monitoring engine with real-time Kismet database queries
- **cyt_gui.py**: Enhanced Tkinter GUI with surveillance analysis and stop comparison capabilities
- **surveillance_analyzer.py**: GPS surveillance detection with automatic coordinate extraction and advanced KML visualization
- **surveillance_detector.py**: Core persistence detection engine for suspicious device patterns
- **gps_tracker.py**: GPS tracking with location clustering and spectacular Google Earth KML generation
- **probe_analyzer.py**: Post-processing tool with WiGLE integration
- **stop_comparison_analyzer.py**: Multi-stop comparison analysis for detecting following behavior
- **start_kismet_clean.sh**: ONLY working Kismet startup script (July 23, 2025 fix)

### Security Components
- **secure_database.py**: SQL injection prevention
- **secure_credentials.py**: Encrypted credential management
- **secure_ignore_loader.py**: Safe ignore list loading
- **secure_main_logic.py**: Secure monitoring logic
- **input_validation.py**: Input sanitization and validation
- **migrate_credentials.py**: Credential migration tool

## Output Files & Project Structure

### Organized Output Directories
- **Surveillance Reports**: `./surveillance_reports/surveillance_report_YYYYMMDD_HHMMSS.md` (markdown)
- **HTML Reports**: `./surveillance_reports/surveillance_report_YYYYMMDD_HHMMSS.html` (styled HTML with pandoc)
- **Stop Comparison Reports**: `./surveillance_reports/stop_comparison_YYYYMMDD_HHMMSS.html` (HTML) and `.txt` (text)
- **KML Visualizations**: `./kml_files/surveillance_analysis_YYYYMMDD_HHMMSS.kml` (spectacular Google Earth files)
- **CYT Logs**: `./logs/cyt_log_MMDDYY_HHMMSS`
- **Analysis Logs**: `./analysis_logs/surveillance_analysis.log`
- **Probe Reports**: `./reports/probe_analysis_report_YYYYMMDD_HHMMSS.txt`

### Configuration & Data
- **Ignore Lists**: `./ignore_lists/mac_list.json`, `./ignore_lists/ssid_list.json`
- **Encrypted Credentials**: `./secure_credentials/encrypted_credentials.json`

### Archive Directories (Cleaned July 23, 2025)
- **old_scripts/**: All broken startup scripts with hanging pkill commands
- **docs_archive/**: Session notes, old configs, backup files, duplicate logs
- **legacy/**: Original legacy code archive (pre-security hardening)

## Technical Architecture

### Time Window System
Maintains four overlapping time windows to detect device persistence:
- Recent: Past 5 minutes
- Medium: 5-10 minutes ago
- Old: 10-15 minutes ago
- Oldest: 15-20 minutes ago

### Surveillance Detection
Advanced persistence detection algorithms analyze device behavior patterns:
- **Temporal Persistence**: Consistent device appearances over time
- **Location Correlation**: Devices following across multiple locations
- **Probe Pattern Analysis**: Suspicious SSID probe requests
- **Timing Analysis**: Unusual appearance patterns
- **Persistence Scoring**: Weighted scores (0-1.0) based on combined indicators
- **Multi-location Tracking**: Specialized algorithms for detecting following behavior

### GPS Integration & Spectacular KML Visualization (Enhanced!)
- **🆕 Automatic GPS extraction** from Kismet database (Bluetooth GPS support)
- **Location clustering** with 100m threshold for grouping nearby coordinates
- **Session management** with timeout handling for location transitions
- **Device-to-location correlation** links Wi-Fi devices to GPS positions
- **Professional KML generation** with spectacular Google Earth visualizations featuring:
  - Color-coded persistence level markers (green/yellow/red)
  - Device tracking paths showing movement correlation
  - Rich interactive balloon content with detailed device intelligence
  - Activity heatmaps and surveillance intensity zones
  - Temporal analysis overlays for time-based pattern detection
- **Multi-location tracking** detects devices following across locations with visual tracking paths

### Stop Comparison Analysis
- **Haversine distance calculation** for accurate GPS proximity matching
- **Configurable search radius** (default 100m) around each stop
- **Multi-category tracking**: BSSIDs, SSIDs, and Probe Requests
- **Minimum occurrence threshold** to filter noise
- **Dual-format reporting**: Text and styled HTML reports

## Configuration

All settings are centralized in `config.json`:
```json
{
  "paths": {
    "kismet_logs": "/path/to/kismet/*.kismet",
    "log_dir": "./logs/"
  },
  "timing": {
    "time_windows": {
      "recent": 5,
      "medium": 10,
      "old": 15,
      "oldest": 20
    }
  },
  "stop_comparison": {
    "enabled": true,
    "radius_meters": 100,
    "minimum_occurrences": 2,
    "stops": []
  }
}
```

WiGLE API credentials are now securely encrypted in `secure_credentials/encrypted_credentials.json`.

## Security Features

- **Parameterized SQL queries** prevent injection attacks
- **Encrypted credential storage** protects API keys
- **Input validation** prevents malicious input
- **Audit logging** tracks all security events
- **Safe ignore list loading** eliminates code execution risks

## Author

@matt0177

## License

MIT License

## Disclaimer

This tool is intended for legitimate security research, network administration, and personal safety purposes. Users are responsible for complying with all applicable laws and regulations in their jurisdiction.
