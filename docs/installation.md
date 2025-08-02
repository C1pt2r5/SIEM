# SIEM System Installation Guide

## Prerequisites

### System Requirements
- **Operating System**: Windows 10/11, Linux (Ubuntu 20.04+), or macOS
- **RAM**: Minimum 8GB, Recommended 16GB+
- **Storage**: Minimum 50GB free space
- **CPU**: 4+ cores recommended
- **Network**: Internet access for downloading components

### Required Software
- **Docker Desktop** (latest version)
- **Docker Compose** (included with Docker Desktop)
- **Git** (for cloning repository)
- **PowerShell** (Windows) or **Bash** (Linux/macOS)

## Installation Steps

### 1. Clone Repository
```bash
git clone <repository-url>
cd siem-system
```

### 2. Windows Installation

#### Quick Start
```powershell
# Run as Administrator
.\start-siem.ps1 -SetupCerts
```

#### Manual Setup
```powershell
# 1. Setup certificates
.\start-siem.ps1 -SetupCerts

# 2. Configure environment
cp .env.example .env
# Edit .env file with your settings

# 3. Start system
docker-compose up -d
```

### 3. Linux/macOS Installation

#### Quick Start
```bash
# Make scripts executable
chmod +x setup-certificates.sh start-siem.sh

# Setup and start
./setup-certificates.sh
./start-siem.sh
```

#### Manual Setup
```bash
# 1. Setup certificates
./setup-certificates.sh

# 2. Configure environment
cp .env.example .env
nano .env  # Edit with your settings

# 3. Start system
docker-compose up -d
```

## Configuration

### Environment Variables
Edit the `.env` file to customize your installation:

```bash
# Elasticsearch Configuration
ELASTIC_PASSWORD=your-secure-password
ELASTIC_USERNAME=elastic

# Alert Configuration
SMTP_HOST=smtp.gmail.com
SMTP_USERNAME=your-email@gmail.com
SMTP_PASSWORD=your-app-password
ALERT_EMAIL=security@yourcompany.com

# Slack Integration (Optional)
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/SLACK/WEBHOOK

# Threat Intelligence APIs (Optional)
ABUSEIPDB_API_KEY=your-abuseipdb-api-key
VIRUSTOTAL_API_KEY=your-virustotal-api-key
```

### SSL Certificates
The system uses self-signed certificates by default. For production:

1. Replace certificates in `certs/` directory
2. Update certificate paths in configuration files
3. Restart services: `docker-compose restart`

## Agent Configuration

### Linux Filebeat Setup
```bash
# 1. Copy configuration
scp config/filebeat/filebeat.yml root@target-server:/etc/filebeat/

# 2. Copy certificates
scp -r certs/ root@target-server:/etc/filebeat/

# 3. Install and start Filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-linux-x86_64.tar.gz
tar xzvf filebeat-8.11.0-linux-x86_64.tar.gz
sudo ./filebeat -e -c /etc/filebeat/filebeat.yml
```

### Windows Winlogbeat Setup
```powershell
# 1. Download Winlogbeat
Invoke-WebRequest -Uri "https://artifacts.elastic.co/downloads/beats/winlogbeat/winlogbeat-8.11.0-windows-x86_64.zip" -OutFile "winlogbeat.zip"
Expand-Archive winlogbeat.zip

# 2. Copy configuration
Copy-Item config\winlogbeat\winlogbeat.yml winlogbeat\winlogbeat.yml

# 3. Copy certificates
Copy-Item -Recurse certs winlogbeat\

# 4. Install and start service
cd winlogbeat
.\install-service-winlogbeat.ps1
Start-Service winlogbeat
```

## Verification

### Check System Status
```bash
# View all services
docker-compose ps

# Check logs
docker-compose logs -f

# Test connectivity
curl -k https://localhost:9200
curl http://localhost:8080/health
```

### Access Web Interfaces
- **SIEM Dashboard**: http://localhost:8080
- **Kibana**: https://localhost:5601
- **Elasticsearch**: https://localhost:9200

Default credentials:
- Username: `elastic`
- Password: `changeme` (change this!)

## Troubleshooting

### Common Issues

#### Elasticsearch Won't Start
```bash
# Check logs
docker-compose logs elasticsearch

# Common fixes:
# 1. Increase Docker memory to 4GB+
# 2. Check disk space
# 3. Verify certificate permissions
sudo chown -R 1000:1000 certs/
```

#### Kibana Connection Issues
```bash
# Verify Elasticsearch is running
curl -k https://localhost:9200

# Check Kibana logs
docker-compose logs kibana

# Reset Kibana data
docker-compose down
docker volume rm siem_elasticsearch_data
docker-compose up -d
```

#### Agent Connection Issues
```bash
# Test Logstash connectivity
telnet localhost 5044

# Check agent logs
sudo journalctl -u filebeat -f

# Verify certificates
openssl verify -CAfile certs/ca/ca.crt certs/filebeat/filebeat.crt
```

### Performance Tuning

#### For High Volume Environments
```yaml
# docker-compose.override.yml
version: '3.8'
services:
  elasticsearch:
    environment:
      - "ES_JAVA_OPTS=-Xms4g -Xmx4g"
    deploy:
      resources:
        limits:
          memory: 8g
  
  logstash:
    environment:
      - "LS_JAVA_OPTS=-Xmx2g -Xms2g"
    deploy:
      resources:
        limits:
          memory: 4g
```

#### Index Optimization
```bash
# Set up index lifecycle management
curl -X PUT "localhost:9200/_ilm/policy/siem-policy" -H 'Content-Type: application/json' -d'
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "5GB",
            "max_age": "1d"
          }
        }
      },
      "delete": {
        "min_age": "30d",
        "actions": {
          "delete": {}
        }
      }
    }
  }
}'
```

## Security Hardening

### Production Checklist
- [ ] Change default passwords
- [ ] Use proper SSL certificates
- [ ] Configure firewall rules
- [ ] Enable audit logging
- [ ] Set up log rotation
- [ ] Configure backup strategy
- [ ] Update threat intelligence feeds
- [ ] Test alert mechanisms
- [ ] Document incident response procedures

### Network Security
```bash
# Restrict access to SIEM ports
sudo ufw allow from 192.168.1.0/24 to any port 5601
sudo ufw allow from 192.168.1.0/24 to any port 8080
sudo ufw deny 9200
```

## Backup and Recovery

### Backup Elasticsearch Data
```bash
# Create snapshot repository
curl -X PUT "localhost:9200/_snapshot/backup" -H 'Content-Type: application/json' -d'
{
  "type": "fs",
  "settings": {
    "location": "/backup"
  }
}'

# Create snapshot
curl -X PUT "localhost:9200/_snapshot/backup/snapshot_1"
```

### Backup Configuration
```bash
# Backup all configurations
tar -czf siem-backup-$(date +%Y%m%d).tar.gz \
  config/ \
  rules/ \
  dashboards/ \
  certs/ \
  .env \
  docker-compose.yml
```

## Support

### Getting Help
- Check logs: `docker-compose logs <service>`
- Review documentation in `docs/` directory
- Check GitHub issues
- Community Discord/Slack

### Reporting Issues
Include the following information:
- Operating system and version
- Docker version
- Error logs
- Configuration files (sanitized)
- Steps to reproduce

---

**Next**: [Configuration Guide](configuration.md)
