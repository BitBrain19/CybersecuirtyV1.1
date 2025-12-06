# Log Ingestion Guide

This guide explains how to feed event logs into the CyberGard AI system for analysis (UEBA, Threat Detection, etc.).

There are three ways to ingest logs:

1.  **Automatic Local Collection** (Easiest, Default)
2.  **Remote Collection** (For other computers)
3.  **Manual API Injection** (For testing/development)

---

## 1. Automatic Local Collection
If your server is running on **Windows**, the system automatically "tails" your Windows Event Logs.

**Steps:**
1.  Start the backend server (`uvicorn app.main:app ...`).
2.  **That's it.** The system will automatically detect new events in:
    *   System Log
    *   Application Log
    *   Security Log
3.  Wait 60 seconds (the default polling interval) for new events to appear in the dashboard.

> **Note:** This only collects logs from the *same machine* running the server.

---

## 2. Remote Collection (Specific Computers)
To collect logs from *other/remote* computers, use the provided Forwarder Script.

**Prerequisites:**
*   Python 3.x installed on the target machine.
*   Network access to your CyberGard server (port 8000 or 443 for HTTPS).

**Steps:**
1.  Locate the script: `backend/scripts/remote_log_forwarder.py`.
2.  Copy this file to the remote computer.
3.  Open a terminal (PowerShell/CMD on Windows, bash on Linux) on that computer.
4.  Run the script, pointing it to your main server's IP address:
    ```bash
    python remote_log_forwarder.py --url http://YOUR_SERVER_IP:8000/api/v1/logs/ingest
    ```

### Using Secure HTTPS with API Key Authentication (Recommended for Production)
For production deployments, use HTTPS with an API key:

```bash
python remote_log_forwarder.py \
  --url https://YOUR_SERVER_IP:8000/api/v1/logs/ingest \
  --api-key YOUR_API_KEY_HERE
```

**Options:**
- `--url` — Backend API endpoint (required)
- `--api-key` — Bearer token for authentication (optional, but recommended)
- `--skip-verify` — Skip TLS certificate verification (use only for testing/self-signed certs)
- `--ca-bundle` — Path to CA certificate bundle (optional, for custom CAs)

### Running in the Background (Persistence)

**On Windows (Interactive):**
```powershell
python remote_log_forwarder.py --url https://YOUR_SERVER_IP:8000/api/v1/logs/ingest --api-key YOUR_API_KEY
```

**On Windows (Background via Scheduled Task - Automated):**
Use the provided `deploy_windows.ps1` script to automate Scheduled Task creation:
```powershell
# Run as Administrator
.\deploy_windows.ps1 `
  -DeviceName "Device01" `
  -ApiUrl "https://YOUR_SERVER_IP:8000/api/v1/logs/ingest" `
  -ApiKey "YOUR_API_KEY_HERE"
```
This will:
- Deploy the forwarder script to `C:\CyberGard\`
- Create a Scheduled Task to run at startup
- Start the service immediately

**On Linux (Background via Systemd):**
Use the provided `deploy_linux.sh` script to automate systemd service creation:
```bash
sudo bash deploy_linux.sh \
  --device-name Device01 \
  --api-url https://YOUR_SERVER_IP:8000/api/v1/logs/ingest \
  --api-key YOUR_API_KEY_HERE
```
This will:
- Deploy the forwarder script to `/opt/cybergard/`
- Create a systemd service
- Enable auto-start on boot
- Start the service immediately

**Check service status (Linux):**
```bash
systemctl status cybergard-forwarder
journalctl -u cybergard-forwarder -f
```

### Bulk Deployment (Multiple Devices)

**Windows (via CSV manifest):**
1. Edit `backend/scripts/devices_manifest.csv` with your device list.
2. Run the bulk deployment script:
   ```powershell
   .\deploy_bulk.ps1 -ManifestFile devices_manifest.csv -ApiUrl https://YOUR_SERVER_IP:8000/api/v1/logs/ingest
   ```

*Tip: For automated remote deployment via SSH or WinRM, modify the scripts to invoke remotely on each host.*

---

## 3. Manual API Injection
You can send raw JSON logs directly to the API for immediate analysis. This is useful for testing or integrating custom applications.

**Endpoint:** `POST /api/v1/logs/ingest`

**Example (cURL):**
```bash
curl -X POST "http://localhost:8000/api/v1/logs/ingest" \
  -H "Content-Type: application/json" \
  -d '[
    {
      "timestamp": "2025-12-06T12:00:00Z",
      "details": {
         "source_ip": "192.168.1.50",
         "event_type": "login_failed",
         "user": "admin",
         "message": "Password mismatch"
      }
    }
  ]'
```

**Response:**
```json
{
  "status": "success",
  "message": "Ingested 1 logs",
  "processed": true
}
```
