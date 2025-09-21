# 3rd Party Tracer

**🔍 Advanced Third-Party Service Discovery Tool**

[![Live Demo](https://img.shields.io/badge/Live%20Demo-3rd%20Party%20Tracer-blue?style=for-the-badge&logo=github)](https://kedster.github.io/3ptracer/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Technology](https://img.shields.io/badge/Technology-HTML%2FJS%2FCSS-orange)](https://developer.mozilla.org/en-US/docs/Web/HTML)

**3rd Party Tracer** is a powerful client-side web application that analyzes DNS records to identify third-party services associated with any domain. Built with pure HTML, JavaScript, and CSS, it provides comprehensive insights into an organization's digital footprint and cloud service dependencies.

## 🌐 Live Application

**🔗 [https://kedster.github.io/3ptracer/](https://kedster.github.io/3ptracer/)**

## 🚀 Deployment Status

### Current Deployment
- **Platform**: GitHub Pages
- **Status**: ✅ Active and Operational
- **URL**: [https://kedster.github.io/3ptracer/](https://kedster.github.io/3ptracer/)
- **Last Updated**: September 21, 2025
- **Features**: Full functionality with direct API calls

### Available Deployment Options
- **GitHub Pages**: ✅ Currently deployed and tested
- **Cloudflare Pages + Workers**: 🔧 Available (requires authentication)

### Worker API Status
- **Cloudflare Worker**: 🔧 Code ready, deployment pending authentication
- **API Endpoints**: Prepared for DNS queries, Certificate Transparency, etc.
- **Fallback Mode**: ✅ Direct API calls working in current deployment

## ✨ Features

### 🔍 **Comprehensive DNS Analysis**
- **DoH (DNS over HTTPS)** queries using Google and Cloudflare DNS servers
- **Multiple DNS record types**: A, CNAME, TXT, MX, NS, SPF, DMARC
- **Certificate Transparency logs** via crt.sh and Cert Spotter
- **Threat intelligence** integration with OTX AlienVault and HackerTarget

### 🏢 **Service Detection & Classification**
- **Cloud Providers**: AWS, Azure, Google Cloud, DigitalOcean, Linode, Vultr
- **Email Services**: ProofPoint, Mimecast, Barracuda, Sophos
- **CDN & Hosting**: Cloudflare, Firebase, GitHub Pages, GitLab Pages
- **DNS Services**: GoDaddy, Namecheap, Google Domains, Route53
- **Security Services**: Various email security and threat protection providers

### 🔒 **Security Analysis**
- **Subdomain takeover detection** via CNAME resolution checks
- **DMARC policy analysis** with detailed policy parsing
- **Security issue categorization** by severity (High, Medium, Low)
- **Infrastructure risk assessment** based on IP ranges and ASN data

### 📊 **Rich Data Visualization**
- **Service categorization** with detailed descriptions
- **Historical subdomain records** with discovery source tracking
- **CNAME mapping visualization** showing service relationships
- **Statistics dashboard** with comprehensive metrics
- **Hyperlinked subdomains** for easy navigation

## 🚀 Technology Stack

- **Frontend**: Pure HTML5, CSS3, Vanilla JavaScript
- **API Proxy**: Cloudflare Workers (with fallback to direct calls)
- **DNS**: DNS over HTTPS (DoH) with multiple providers
- **APIs**: Certificate Transparency, Threat Intelligence, ASN Lookup
- **Architecture**: Client-side with optional Worker backend
- **Deployment**: Cloudflare Pages + Workers (recommended) or GitHub Pages

## 🌐 Deployment Options

### GitHub Pages (Currently Active)

The application is currently deployed on GitHub Pages with direct API calls:

**🔗 Live Application: [https://kedster.github.io/3ptracer/](https://kedster.github.io/3ptracer/)**

```bash
# Deploy to GitHub Pages
./deploy.sh  # Builds to docs/ folder for GitHub Pages
```

### Cloudflare Pages + Workers (Available)

Deploy with advanced features including API proxy, caching, and CORS handling:

```bash
# Install Wrangler CLI
npm install -g wrangler

# Authenticate with Cloudflare
wrangler login

# Deploy (automated script)
./deploy-cloudflare.sh
```

See [CLOUDFLARE-DEPLOYMENT.md](CLOUDFLARE-DEPLOYMENT.md) for detailed instructions.

> **Note**: The Cloudflare deployment requires authentication and setup. The repository includes all necessary files for Cloudflare deployment but is currently deployed on GitHub Pages.

## 📋 How It Works

### 1. **DNS Record Analysis**
The tool starts by querying various DNS record types:
- **TXT records** reveal service ownership proofs and configurations
- **SPF records** identify authorized email service providers
- **DMARC records** show email security and reporting services
- **MX records** indicate email hosting providers

### 2. **Subdomain Discovery**
Leverages multiple sources for comprehensive subdomain enumeration:
- **Certificate Transparency logs** via crt.sh and Cert Spotter
- **Threat intelligence platforms** like OTX AlienVault
- **DNS enumeration APIs** for additional coverage

### 3. **Service Classification**
Each discovered subdomain is analyzed and categorized:
- **IP-based classification** using ASN data from ipinfo.io
- **CNAME target analysis** for service identification
- **Pattern matching** against known service providers
- **Vendor consolidation** to prevent duplicate entries

### 4. **Security Assessment**
Comprehensive security analysis including:
- **Subdomain takeover detection** via CNAME resolution
- **DMARC policy evaluation** with detailed tag parsing
- **Infrastructure risk assessment** based on IP ranges
- **Cloud service dependency mapping**

## 🛠️ Installation & Usage

### **Quick Start**
1. Clone the repository:
   ```bash
   git clone https://github.com/kedster/3ptracer.git
   cd 3ptracer
   ```

2. Open `index.html` in your browser or serve locally:
   ```bash
   # Using Python
   python -m http.server 8000
   
   # Using Node.js
   npx serve .
   ```

3. Enter a domain name and click "Analyze Domain"

### **Production Deployment**
Use the included deployment script:
```bash
./deploy.sh
```

## 📁 Project Structure

```
3ptracer/
├── index.html              # Main application HTML
├── style.css               # Application styles
├── app.js                  # Main application logic
├── dns-analyzer.js         # DNS analysis engine
├── service-patterns.js     # Service detection patterns
├── service-registry.js     # Service management
├── subdomain-registry.js   # Subdomain tracking
├── deploy.sh               # Production deployment script
└── docs/                   # Production build (auto-generated)
```

## 🔧 Key Components

### **DNS Analyzer (`dns-analyzer.js`)**
- Handles all DNS queries using DoH
- Manages rate limiting and error handling
- Integrates with multiple APIs for subdomain discovery
- Processes various DNS record types

### **Service Registry (`service-registry.js`)**
- Manages service detection and categorization
- Handles vendor consolidation and deduplication
- Maintains service metadata and descriptions
- Provides service statistics

### **Service Patterns (`service-patterns.js`)**
- Contains regex patterns for service detection
- Maps domains to vendor categories
- Includes IP range classifications
- Supports custom service definitions

### **Subdomain Registry (`subdomain-registry.js`)**
- Tracks discovered subdomains
- Manages subdomain metadata
- Handles CNAME chain resolution
- Provides subdomain statistics

## 🌟 Features in Detail

### **Service Detection**
- **Pattern-based matching** for known service providers
- **IP range analysis** for cloud provider identification
- **CNAME target analysis** for service mapping
- **Vendor consolidation** to prevent duplicates

### **Security Analysis**
- **Subdomain takeover detection** via CNAME resolution
- **DMARC policy parsing** with detailed tag analysis
- **Security issue categorization** by severity
- **Infrastructure risk assessment**

### **Data Visualization**
- **Categorized service display** with descriptions
- **Historical record tracking** with discovery sources
- **CNAME mapping visualization**
- **Comprehensive statistics dashboard**

## 🔒 Privacy & Security

- **Client-side only**: No data sent to external servers
- **DNS over HTTPS**: Encrypted DNS queries
- **No tracking**: No analytics or user tracking
- **Open source**: Transparent code for security review

## 🤝 Contributing

We welcome contributions! Please feel free to submit issues, feature requests, or pull requests.

### **Development Setup**
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🙏 Acknowledgments

- **Cyfinoid Research** for cutting-edge cloud security research
- **Certificate Transparency** logs for subdomain discovery
- **DNS over HTTPS** providers for secure DNS resolution
- **Threat intelligence platforms** for comprehensive data

## 📞 Support

For questions, issues, or feature requests:
- **GitHub Issues**: [Create an issue](https://github.com/kedster/3ptracer/issues)
- **Live Demo**: [https://kedster.github.io/3ptracer/](https://kedster.github.io/3ptracer/)

--- 

