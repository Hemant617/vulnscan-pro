# API Documentation

## Base URL
```
http://localhost:5000/api
```

## Authentication
Currently, the API does not require authentication. In production, implement proper authentication mechanisms.

## Endpoints

### 1. Start a New Scan

**POST** `/api/scan/start`

Start a new vulnerability scan.

**Request Body:**
```json
{
  "target": "https://example.com",
  "scan_type": "standard",
  "options": {
    "portScan": true,
    "serviceScan": true,
    "webScan": false
  }
}
```

**Parameters:**
- `target` (string, required): Target URL or IP address
- `scan_type` (string, optional): Type of scan - "quick", "standard", or "deep" (default: "standard")
- `options` (object, optional): Scan options

**Response:**
```json
{
  "success": true,
  "scan_id": 1,
  "message": "Scan started successfully"
}
```

**Example:**
```bash
curl -X POST http://localhost:5000/api/scan/start \
  -H "Content-Type: application/json" \
  -d '{
    "target": "192.168.1.1",
    "scan_type": "standard"
  }'
```

---

### 2. Get Scan Status

**GET** `/api/scan/<scan_id>/status`

Get the current status and progress of a scan.

**Response:**
```json
{
  "scan_id": 1,
  "status": "running",
  "progress": 45,
  "current_task": "Detecting services...",
  "started_at": "2024-12-25T10:30:00",
  "completed_at": null
}
```

**Status Values:**
- `pending`: Scan is queued
- `running`: Scan is in progress
- `completed`: Scan finished successfully
- `failed`: Scan encountered an error

**Example:**
```bash
curl http://localhost:5000/api/scan/1/status
```

---

### 3. Get Scan Results

**GET** `/api/scan/<scan_id>/results`

Retrieve detailed results of a completed scan.

**Response:**
```json
{
  "scan_id": 1,
  "target": "192.168.1.1",
  "scan_type": "standard",
  "status": "completed",
  "risk_score": 65,
  "severity_counts": {
    "critical": 2,
    "high": 3,
    "medium": 5,
    "low": 4
  },
  "vulnerabilities": [
    {
      "id": 1,
      "title": "Open Telnet Port",
      "severity": "critical",
      "description": "Port 23 (Telnet) is open and accessible...",
      "recommendation": "Close port 23 and use SSH instead...",
      "cve": null,
      "port": 23,
      "service": "telnet"
    }
  ],
  "created_at": "2024-12-25T10:30:00",
  "completed_at": "2024-12-25T10:45:00"
}
```

**Example:**
```bash
curl http://localhost:5000/api/scan/1/results
```

---

### 4. List All Scans

**GET** `/api/scans`

Get a paginated list of all scans.

**Query Parameters:**
- `page` (integer, optional): Page number (default: 1)
- `per_page` (integer, optional): Items per page (default: 20)

**Response:**
```json
{
  "scans": [
    {
      "id": 1,
      "target": "192.168.1.1",
      "scan_type": "standard",
      "status": "completed",
      "risk_score": 65,
      "created_at": "2024-12-25T10:30:00"
    }
  ],
  "total": 50,
  "pages": 3,
  "current_page": 1
}
```

**Example:**
```bash
curl "http://localhost:5000/api/scans?page=1&per_page=10"
```

---

### 5. Delete a Scan

**DELETE** `/api/scan/<scan_id>`

Delete a scan and all its associated vulnerabilities.

**Response:**
```json
{
  "success": true,
  "message": "Scan deleted successfully"
}
```

**Example:**
```bash
curl -X DELETE http://localhost:5000/api/scan/1
```

---

## Error Responses

All endpoints may return error responses in the following format:

```json
{
  "error": "Error message description"
}
```

**Common HTTP Status Codes:**
- `200 OK`: Request successful
- `400 Bad Request`: Invalid request parameters
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

---

## Rate Limiting

Currently, no rate limiting is implemented. For production use, implement rate limiting to prevent abuse.

---

## Python Client Example

```python
import requests
import time

# Start a scan
response = requests.post('http://localhost:5000/api/scan/start', json={
    'target': '192.168.1.1',
    'scan_type': 'standard'
})
scan_id = response.json()['scan_id']

# Monitor progress
while True:
    status = requests.get(f'http://localhost:5000/api/scan/{scan_id}/status').json()
    print(f"Progress: {status['progress']}% - {status['current_task']}")
    
    if status['status'] == 'completed':
        break
    
    time.sleep(2)

# Get results
results = requests.get(f'http://localhost:5000/api/scan/{scan_id}/results').json()
print(f"Risk Score: {results['risk_score']}/100")
print(f"Vulnerabilities found: {len(results['vulnerabilities'])}")
```

---

## JavaScript Client Example

```javascript
// Start a scan
fetch('http://localhost:5000/api/scan/start', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    target: '192.168.1.1',
    scan_type: 'standard'
  })
})
.then(res => res.json())
.then(data => {
  const scanId = data.scan_id;
  
  // Monitor progress
  const interval = setInterval(() => {
    fetch(`http://localhost:5000/api/scan/${scanId}/status`)
      .then(res => res.json())
      .then(status => {
        console.log(`Progress: ${status.progress}%`);
        
        if (status.status === 'completed') {
          clearInterval(interval);
          
          // Get results
          fetch(`http://localhost:5000/api/scan/${scanId}/results`)
            .then(res => res.json())
            .then(results => {
              console.log('Scan completed!', results);
            });
        }
      });
  }, 2000);
});
```
