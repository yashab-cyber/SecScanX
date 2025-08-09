# 🛡️ SecScanX

**AI-Assisted Vulnerability Assessment & Penetration Testing Tool**

SecScanX is an open-source security scanning platform that combines traditional penetration testing tools with artificial intelligence to provide comprehensive vulnerability assessments. Designed for beginners, researchers, and security professionals, it offers automated reconnaissance, intelligent analysis, and detailed reporting.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![React](https://img.shields.io/badge/React-18+-61DAFB.svg)](https://reactjs.org/)

## 🔧 Features

| Category | Features |
|----------|----------|
| ✅ **Reconnaissance** | Subdomain finder, WHOIS lookup, port scanning, DNS enumeration |
| 🧠 **AI Assistant** | Interprets scan results, suggests next steps, explains findings |
| 🚀 **Automation** | Automated comprehensive scans via CLI or web interface |
| 📊 **Reports** | Generates professional PDF and HTML reports |
| 👥 **Multi-user** | Team collaboration with project management and audit logs |
| 🎯 **Learning Mode** | Educational explanations for students and beginners |
| ☁️ **API Ready** | RESTful API for integration and automation |
| 🔒 **Security** | Rate limiting, authentication, and secure configurations |

## 🚀 Quick Start

### Prerequisites

- Python 3.8+ and pip
- Node.js 16+ and npm
- nmap, dnsutils, whois (installed automatically)

### Installation

```bash
# Clone the repository
git clone https://github.com/yashab-cyber/SecScanX.git
cd SecScanX

# Run the installation script (Ubuntu/Debian)
chmod +x scripts/install.sh
./scripts/install.sh

# Or install manually:
# Backend setup
cd backend
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Frontend setup
cd ../frontend
npm install

# CLI setup
cd ../cli
pip3 install -r requirements.txt
chmod +x secscanx.py
```

### Configuration

```bash
# Copy and edit environment file
cp .env.example .env
# Edit .env with your settings (API keys, database config, etc.)
```

### Running SecScanX

**Start the Backend API:**
```bash
cd backend
source venv/bin/activate
python app.py
# API available at http://localhost:5000
```

**Start the Frontend (new terminal):**
```bash
cd frontend
npm start
# Web interface at http://localhost:3000
```

**Use the CLI:**
```bash
# Add to PATH or use directly
./cli/secscanx.py --help

# Example scans
secscanx subdomain example.com
secscanx port 192.168.1.1 --port-range 1-1000
secscanx vuln https://example.com --scan-type web
```

## 📖 Usage Examples

### Web Interface

1. **Dashboard**: View scan statistics, recent results, and quick actions
2. **Scanner**: Configure and run different types of security scans
3. **Results**: Analyze findings with AI-powered insights
4. **Reports**: Generate professional security assessment reports
5. **AI Assistant**: Chat with AI for security advice and explanations

### Command Line Interface

```bash
# Comprehensive subdomain enumeration
secscanx subdomain target.com --output results.json

# Port scan with custom range
secscanx port 10.0.0.1 --port-range 1-65535

# Web application vulnerability assessment
secscanx vuln https://target.com --scan-type comprehensive

# DNS reconnaissance
secscanx dns target.com

# Generate professional report
secscanx report results.json --format pdf
```

### API Usage

```python
import requests

# Start a subdomain scan
response = requests.post('http://localhost:5000/api/scan/subdomain', 
                        json={'domain': 'example.com'})
result = response.json()

# Get AI analysis
ai_response = requests.post('http://localhost:5000/api/ai/chat',
                           json={'message': 'Explain this vulnerability', 
                                'context': result})
```

## 🏗️ Architecture

SecScanX follows a modular architecture:

```
SecScanX/
├── backend/          # Python Flask API server
│   ├── app.py       # Main application
│   ├── modules/     # Scanning and AI modules
│   └── models/      # Database models
├── frontend/         # React web interface
│   ├── src/
│   └── components/
├── cli/             # Command-line interface
├── reports/         # Generated reports
├── docs/           # Documentation
└── scripts/        # Installation and utility scripts
```

### Key Components

- **Reconnaissance Module**: Subdomain enumeration, port scanning, DNS/WHOIS lookups
- **AI Assistant**: OpenAI integration for intelligent analysis and recommendations
- **Vulnerability Scanner**: Web app and network service security assessment
- **Report Generator**: Professional PDF/HTML report creation
- **Multi-user System**: Authentication, projects, and audit logging

## 🔍 Scan Types

### 1. Subdomain Enumeration
- Brute force common subdomains
- Certificate Transparency log search
- DNS zone transfer attempts
- AI analysis of discovered subdomains

### 2. Port Scanning
- TCP/UDP port discovery
- Service version detection
- Operating system fingerprinting
- Risk assessment of open services

### 3. Vulnerability Assessment
- Web application security testing
- Network service vulnerability detection
- SSL/TLS configuration analysis
- Security header verification

### 4. DNS Enumeration
- A, AAAA, MX, NS, TXT record collection
- DNS zone information gathering
- Email server discovery
- Infrastructure mapping

### 5. WHOIS Lookup
- Domain registration information
- Ownership and contact details
- Name server identification
- Expiration date monitoring

## 🤖 AI Features

SecScanX integrates AI to enhance security assessments:

- **Intelligent Analysis**: Automatically interprets scan results
- **Risk Assessment**: Prioritizes findings by severity and impact
- **Remediation Guidance**: Provides specific fix recommendations
- **Learning Mode**: Explains techniques for educational purposes
- **Contextual Chat**: Interactive AI assistant for security questions

## 📊 Reporting

Generate professional security reports in multiple formats:

- **HTML Reports**: Interactive web-based reports with charts
- **PDF Reports**: Professional documents for stakeholders
- **JSON Exports**: Machine-readable data for integration
- **Executive Summaries**: High-level findings for management

## 🔐 Security Considerations

**Important**: SecScanX is designed for authorized security testing only.

- Only scan systems you own or have explicit permission to test
- Some scans may be detected by security systems
- Follow responsible disclosure practices
- Respect rate limits and target system resources
- Review local laws and regulations before testing

## 🤝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup

```bash
# Clone and setup development environment
git clone https://github.com/yashab-cyber/SecScanX.git
cd SecScanX

# Install development dependencies
pip install -r backend/requirements-dev.txt
npm install --dev --prefix frontend

# Run tests
pytest backend/tests/
npm test --prefix frontend
```

## 💰 Support SecScanX

Help us improve SecScanX by supporting the development! Your donations enable us to:

- 🚀 **Develop new features** - Advanced scanning modules and AI capabilities
- 🔒 **Enhance security** - Better vulnerability detection and exploit research
- 📚 **Create educational content** - Tutorials and penetration testing resources
- 🌍 **Grow the community** - Support contributors and maintain infrastructure

### 🌟 Donation Methods

**Cryptocurrency (Preferred):**
- **Solana (SOL):** `5pEwP9JN8tRCXL5Vc9gQrxRyHHyn7J6P2DCC8cSQKDKT`
- **Bitcoin (BTC):** `bc1qmkptg6wqn9sjlx6wf7dk0px0yq4ynr4ukj2x8c`
- **Ethereum (ETH):** Contact yashabalam707@gmail.com for current address

**Traditional Methods:**
- **PayPal:** yashabalam707@gmail.com
- **Direct Link:** [paypal.me/yashab07](https://paypal.me/yashab07)

### 🎁 Supporter Benefits

All donors receive:
- 📧 Exclusive monthly newsletter with security insights
- 🎮 Early access to beta features and new scanning modules
- 💬 Access to private contributor community
- 📚 Advanced penetration testing resources and methodologies

**[📋 View Full Donation Details](DONATE.md)**

## 🏆 Connect with ZehraSec

**Official Channels:**
- 🌐 **Website:** [www.zehrasec.com](https://www.zehrasec.com)
- 📸 **Instagram:** [@_zehrasec](https://www.instagram.com/_zehrasec?igsh=bXM0cWl1ejdoNHM4)
- 📘 **Facebook:** [ZehraSec Official](https://www.facebook.com/profile.php?id=61575580721849)
- 🐦 **X (Twitter):** [@zehrasec](https://x.com/zehrasec?t=Tp9LOesZw2d2yTZLVo0_GA&s=08)
- 💼 **LinkedIn:** [ZehraSec Company](https://www.linkedin.com/company/zehrasec)

**Connect with Yashab Alam (Creator):**
- 💻 **GitHub:** [@yashab-cyber](https://github.com/yashab-cyber)
- 📸 **Instagram:** [@yashab.alam](https://www.instagram.com/yashab.alam)
- 💼 **LinkedIn:** [Yashab Alam](https://www.linkedin.com/in/yashab-alam)

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- Built with Flask, React, and modern web technologies
- Integrates nmap, dnspython, and other security tools
- UI components from Material-UI
- Charts powered by Recharts
- AI capabilities via OpenAI API

## 📞 Support

- 📚 **Documentation**: [Wiki](https://github.com/yashab-cyber/SecScanX/wiki)
- 🐛 **Bug Reports**: [Issues](https://github.com/yashab-cyber/SecScanX/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/yashab-cyber/SecScanX/discussions)
- 📧 **Email**: yashabalam707@gmail.com
- 💰 **Donations**: [Support Development](DONATE.md)

## ⚠️ Disclaimer

SecScanX is for educational and authorized testing purposes only. Users are responsible for complying with applicable laws and obtaining proper authorization before scanning any systems. The developers assume no liability for misuse of this tool.

---

**Made with ❤️ by Yashab Alam (Founder of ZehraSec) for the cybersecurity community**