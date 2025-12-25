# Installation Guide

## Quick Start

### Option 1: Local Installation

1. **Clone the repository**
```bash
git clone https://github.com/Hemant617/vulnscan-pro.git
cd vulnscan-pro
```

2. **Install system dependencies**

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install -y python3 python3-pip python3-venv nmap
```

**macOS:**
```bash
brew install python nmap
```

**Windows:**
- Install Python from https://www.python.org/downloads/
- Install Nmap from https://nmap.org/download.html

3. **Create virtual environment**
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

4. **Install Python dependencies**
```bash
pip install -r requirements.txt
```

5. **Initialize database**
```bash
python init_db.py
```

6. **Configure environment (optional)**
```bash
cp .env.example .env
# Edit .env with your settings
```

7. **Run the application**
```bash
python app.py
```

Access at: http://localhost:5000

### Option 2: Docker Installation

1. **Using Docker Compose (Recommended)**
```bash
git clone https://github.com/Hemant617/vulnscan-pro.git
cd vulnscan-pro
docker-compose up -d
```

2. **Using Docker only**
```bash
docker build -t vulnscan-pro .
docker run -p 5000:5000 vulnscan-pro
```

Access at: http://localhost:5000

## OWASP ZAP Setup (Optional)

For web vulnerability scanning, install OWASP ZAP:

### Linux
```bash
wget https://github.com/zaproxy/zaproxy/releases/download/v2.14.0/ZAP_2.14.0_Linux.tar.gz
tar -xvf ZAP_2.14.0_Linux.tar.gz
cd ZAP_2.14.0
./zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

### macOS
```bash
brew install --cask owasp-zap
# Start ZAP in daemon mode
/Applications/OWASP\ ZAP.app/Contents/Java/zap.sh -daemon -host 0.0.0.0 -port 8080
```

### Docker
```bash
docker run -p 8080:8080 owasp/zap2docker-stable zap.sh -daemon -host 0.0.0.0 -port 8080 -config api.disablekey=true
```

## Troubleshooting

### Nmap Permission Issues
```bash
# Linux/macOS - Run with sudo or add capabilities
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip $(which nmap)
```

### Database Issues
```bash
# Reset database
rm vulnscan.db
python init_db.py
```

### Port Already in Use
```bash
# Change port in app.py or use environment variable
export FLASK_RUN_PORT=5001
python app.py
```

## Production Deployment

### Using Gunicorn
```bash
gunicorn --bind 0.0.0.0:5000 --workers 4 app:app
```

### Using Nginx (Reverse Proxy)
```nginx
server {
    listen 80;
    server_name your-domain.com;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Environment Variables
```bash
export SECRET_KEY="your-production-secret-key"
export FLASK_ENV="production"
export DATABASE_URL="sqlite:///vulnscan.db"
```

## Security Considerations

1. **Change default secret key** in production
2. **Use HTTPS** for production deployments
3. **Restrict access** to authorized users only
4. **Regular updates** of dependencies
5. **Firewall rules** to protect the application
6. **Backup database** regularly

## Next Steps

- Read the [Usage Guide](USAGE.md)
- Check [API Documentation](API.md)
- Review [Security Best Practices](SECURITY.md)
