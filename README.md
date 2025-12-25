# 🛡️ VulnScan Pro

**Automated Vulnerability Scanner for Small Businesses**

A comprehensive Python-based security scanning tool that helps small businesses identify and remediate security vulnerabilities in their infrastructure.

## 🚀 Features

- **Port Scanning**: Network reconnaissance using Nmap
- **Web Application Security**: OWASP ZAP API integration for web vulnerability scanning
- **Interactive Dashboard**: Flask-based web interface for managing scans
- **Persistent Storage**: SQLite database for scan history and results
- **Real-time Scanning**: Live progress updates during scans
- **Detailed Reports**: Comprehensive vulnerability reports with remediation steps
- **Risk Scoring**: Automated risk assessment (0-100 scale)

## 🛠️ Technology Stack

- **Python 3.8+**
- **Nmap**: Network scanning and port detection
- **OWASP ZAP API**: Web application security testing
- **Flask**: Web dashboard and API
- **SQLite**: Database for scan results
- **Bootstrap 5**: Responsive UI design

## 📋 Prerequisites

### System Requirements
- Python 3.8 or higher
- Nmap installed on your system
- OWASP ZAP (for web scanning features)

### Install Nmap
```bash
# Ubuntu/Debian
sudo apt-get install nmap

# macOS
brew install nmap

# Windows
# Download from https://nmap.org/download.html
```

### Install OWASP ZAP (Optional for web scanning)
```bash
# Download from https://www.zaproxy.org/download/
```

## 🔧 Installation

1. **Clone the repository**
```bash
git clone https://github.com/Hemant617/vulnscan-pro.git
cd vulnscan-pro
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Initialize database**
```bash
python init_db.py
```

5. **Configure settings** (optional)
```bash
cp config.example.py config.py
# Edit config.py with your settings
```

## 🚀 Usage

### Start the Application
```bash
python app.py
```

Access the dashboard at: `http://localhost:5000`

### Command Line Interface
```bash
# Quick port scan
python scanner.py --target 192.168.1.1 --type port

# Web vulnerability scan
python scanner.py --target https://example.com --type web

# Full scan
python scanner.py --target example.com --type full
```

## 📊 Dashboard Features

### 1. **Scan Management**
- Create new scans with custom parameters
- View scan history
- Real-time scan progress

### 2. **Vulnerability Reports**
- Severity-based categorization (Critical, High, Medium, Low)
- Detailed vulnerability descriptions
- Remediation recommendations
- CVE references

### 3. **Risk Assessment**
- Automated risk scoring
- Compliance checking (OWASP Top 10, CWE)
- Trend analysis

## 🔒 Security Considerations

⚠️ **Important**: This tool is designed for authorized security testing only.

- Only scan systems you own or have explicit permission to test
- Unauthorized scanning may be illegal in your jurisdiction
- Use responsibly and ethically
- Follow responsible disclosure practices

## 📁 Project Structure

```
vulnscan-pro/
├── app.py                 # Flask application
├── scanner.py             # Core scanning logic
├── models.py              # Database models
├── init_db.py            # Database initialization
├── config.py             # Configuration settings
├── requirements.txt      # Python dependencies
├── static/
│   ├── css/
│   │   └── style.css    # Custom styles
│   └── js/
│       └── main.js      # Frontend JavaScript
├── templates/
│   ├── index.html       # Dashboard home
│   ├── scan.html        # Scan interface
│   └── results.html     # Results display
└── utils/
    ├── nmap_scanner.py  # Nmap integration
    ├── zap_scanner.py   # OWASP ZAP integration
    └── report_gen.py    # Report generation
```

## 🧪 Testing

```bash
# Run tests
python -m pytest tests/

# Run with coverage
python -m pytest --cov=. tests/
```

## 📈 Roadmap

- [ ] PDF report generation
- [ ] Email notifications
- [ ] Scheduled scans
- [ ] Multi-user support
- [ ] API authentication
- [ ] Docker containerization
- [ ] Cloud deployment support
- [ ] Integration with SIEM tools

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and authorized security testing purposes only. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before scanning any systems.

## 👨‍💻 Author

**Anmol Kaushal**
- Email: kaushalanmol898@gmail.com
- GitHub: [@Hemant617](https://github.com/Hemant617)

## 🙏 Acknowledgments

- OWASP for security standards and ZAP tool
- Nmap project for network scanning capabilities
- Flask community for the excellent web framework

---

**Built with ❤️ for Small Business Security**
