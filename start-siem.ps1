# SIEM System Startup Script for Windows
# PowerShell script to initialize and start the SIEM system

param(
    [switch]$SetupCerts = $false,
    [switch]$SkipBuild = $false,
    [string]$Environment = "development"
)

Write-Host "🛡️  Starting SIEM System Setup..." -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Check prerequisites
Write-Host "Checking prerequisites..." -ForegroundColor Yellow

# Check Docker
try {
    $dockerVersion = docker --version
    Write-Host "✅ Docker found: $dockerVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker not found. Please install Docker Desktop." -ForegroundColor Red
    exit 1
}

# Check Docker Compose
try {
    $composeVersion = docker-compose --version
    Write-Host "✅ Docker Compose found: $composeVersion" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker Compose not found. Please install Docker Compose." -ForegroundColor Red
    exit 1
}

# Setup certificates if requested
if ($SetupCerts) {
    Write-Host "Setting up certificates..." -ForegroundColor Yellow
    
    # Check if OpenSSL is available (via Git Bash or WSL)
    $opensslPath = $null
    
    # Try Git Bash OpenSSL first
    if (Test-Path "C:\Program Files\Git\usr\bin\openssl.exe") {
        $opensslPath = "C:\Program Files\Git\usr\bin\openssl.exe"
    } elseif (Get-Command wsl -ErrorAction SilentlyContinue) {
        Write-Host "Using WSL for certificate generation..." -ForegroundColor Yellow
        wsl bash -c "./setup-certificates.sh"
    } else {
        Write-Host "⚠️  OpenSSL not found. Creating simple certificates..." -ForegroundColor Yellow
        
        # Create certificate directories
        New-Item -ItemType Directory -Force -Path "certs\ca", "certs\elasticsearch", "certs\kibana", "certs\logstash", "certs\filebeat", "certs\winlogbeat" | Out-Null
        
        # Create dummy certificates (for development only)
        @"
-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAKL0UG+jXKhYMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMjMwMTAxMDAwMDAwWhcNMjQwMTAxMDAwMDAwWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEA2Z3QX0BTLS2Dn1VjbNJKEAEOeJzUpDKjdJz5cJz5cJz5cJz5cJz5cJz5
cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5
cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5
cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5
cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5
cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5cJz5
QIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAzQX0BTLS2Dn1VjbNJKEAEOeJzUpDK
-----END CERTIFICATE-----
"@ | Out-File -FilePath "certs\ca\ca.crt" -Encoding ASCII
        
        # Copy CA cert to other directories
        Copy-Item "certs\ca\ca.crt" -Destination "certs\elasticsearch\elasticsearch.crt"
        Copy-Item "certs\ca\ca.crt" -Destination "certs\kibana\kibana.crt"
        Copy-Item "certs\ca\ca.crt" -Destination "certs\logstash\logstash.crt"
        Copy-Item "certs\ca\ca.crt" -Destination "certs\filebeat\filebeat.crt"
        Copy-Item "certs\ca\ca.crt" -Destination "certs\winlogbeat\winlogbeat.crt"
        
        # Create dummy private keys
        @"
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDZndBfQFMtLYOf
VWNs0koQAQ54nNSkMqN0nPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPl
wnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlw
nPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlw
nPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlw
nPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlw
nPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlwnPlw
QIDAQABAoIBAQCZndBfQFMtLYOfVWNs0koQAQ54nNSkMqN0nPlwnPlwnPlwnPl
-----END PRIVATE KEY-----
"@ | Out-File -FilePath "certs\ca\ca.key" -Encoding ASCII
        
        # Copy keys
        Copy-Item "certs\ca\ca.key" -Destination "certs\elasticsearch\elasticsearch.key"
        Copy-Item "certs\ca\ca.key" -Destination "certs\kibana\kibana.key"
        Copy-Item "certs\ca\ca.key" -Destination "certs\logstash\logstash.key"
        Copy-Item "certs\ca\ca.key" -Destination "certs\filebeat\filebeat.key"
        Copy-Item "certs\ca\ca.key" -Destination "certs\winlogbeat\winlogbeat.key"
        
        Write-Host "⚠️  Development certificates created. Use proper certificates in production!" -ForegroundColor Yellow
    }
    
    Write-Host "✅ Certificates setup completed" -ForegroundColor Green
}

# Create necessary directories
Write-Host "Creating directories..." -ForegroundColor Yellow
$directories = @(
    "logs",
    "data\elasticsearch",
    "data\redis",
    "dashboards",
    "scripts"
)

foreach ($dir in $directories) {
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
}

# Set environment variables
Write-Host "Setting up environment..." -ForegroundColor Yellow
$env:COMPOSE_PROJECT_NAME = "siem"
$env:ELASTIC_VERSION = "8.11.0"

# Build custom images if not skipping
if (-not $SkipBuild) {
    Write-Host "Building custom Docker images..." -ForegroundColor Yellow
    docker-compose build --no-cache siem-web
}

# Start the SIEM system
Write-Host "Starting SIEM system..." -ForegroundColor Yellow
Write-Host "This may take several minutes on first run..." -ForegroundColor Cyan

try {
    # Start core services first
    docker-compose up -d elasticsearch redis
    
    Write-Host "Waiting for Elasticsearch to be ready..." -ForegroundColor Yellow
    $maxAttempts = 30
    $attempt = 0
    
    do {
        Start-Sleep -Seconds 10
        $attempt++
        Write-Host "Checking Elasticsearch... (attempt $attempt/$maxAttempts)" -ForegroundColor Gray
        
        try {
            $response = Invoke-WebRequest -Uri "https://localhost:9200" -SkipCertificateCheck -TimeoutSec 5 -ErrorAction SilentlyContinue
            if ($response.StatusCode -eq 401) {
                Write-Host "✅ Elasticsearch is responding" -ForegroundColor Green
                break
            }
        } catch {
            # Continue waiting
        }
        
        if ($attempt -ge $maxAttempts) {
            Write-Host "❌ Elasticsearch failed to start within timeout" -ForegroundColor Red
            exit 1
        }
    } while ($true)
    
    # Start remaining services
    Write-Host "Starting remaining services..." -ForegroundColor Yellow
    docker-compose up -d
    
    Write-Host "✅ SIEM system started successfully!" -ForegroundColor Green
    
} catch {
    Write-Host "❌ Error starting SIEM system: $_" -ForegroundColor Red
    exit 1
}

# Display access information
Write-Host ""
Write-Host "🎉 SIEM System is now running!" -ForegroundColor Green
Write-Host "================================" -ForegroundColor Green
Write-Host ""
Write-Host "Access URLs:" -ForegroundColor Cyan
Write-Host "• SIEM Web Interface: http://localhost:8080" -ForegroundColor White
Write-Host "• Kibana Dashboard:   https://localhost:5601" -ForegroundColor White
Write-Host "• Elasticsearch:      https://localhost:9200" -ForegroundColor White
Write-Host ""
Write-Host "Default Credentials:" -ForegroundColor Cyan
Write-Host "• Username: elastic" -ForegroundColor White
Write-Host "• Password: changeme" -ForegroundColor White
Write-Host ""
Write-Host "Useful Commands:" -ForegroundColor Cyan
Write-Host "• View logs:          docker-compose logs -f" -ForegroundColor White
Write-Host "• Stop system:        docker-compose down" -ForegroundColor White
Write-Host "• Restart service:    docker-compose restart <service>" -ForegroundColor White
Write-Host "• System status:      docker-compose ps" -ForegroundColor White
Write-Host ""
Write-Host "Next Steps:" -ForegroundColor Yellow
Write-Host "1. Configure agents on target systems" -ForegroundColor White
Write-Host "2. Import Kibana dashboards" -ForegroundColor White
Write-Host "3. Configure alert notifications" -ForegroundColor White
Write-Host "4. Update threat intelligence API keys" -ForegroundColor White
Write-Host ""

# Open browser preview
Write-Host "Opening browser preview..." -ForegroundColor Yellow
Start-Sleep -Seconds 5

# Check if services are responding
$webHealthy = $false
$kibanaHealthy = $false

try {
    $webResponse = Invoke-WebRequest -Uri "http://localhost:8080/health" -TimeoutSec 5 -ErrorAction SilentlyContinue
    if ($webResponse.StatusCode -eq 200) {
        $webHealthy = $true
        Write-Host "✅ SIEM Web Interface is healthy" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠️  SIEM Web Interface not yet ready" -ForegroundColor Yellow
}

try {
    $kibanaResponse = Invoke-WebRequest -Uri "https://localhost:5601" -SkipCertificateCheck -TimeoutSec 5 -ErrorAction SilentlyContinue
    if ($kibanaResponse.StatusCode -eq 200 -or $kibanaResponse.StatusCode -eq 302) {
        $kibanaHealthy = $true
        Write-Host "✅ Kibana is healthy" -ForegroundColor Green
    }
} catch {
    Write-Host "⚠️  Kibana not yet ready" -ForegroundColor Yellow
}

if ($webHealthy) {
    Start-Process "http://localhost:8080"
} else {
    Write-Host "Web interface will be available at http://localhost:8080 once fully started" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "🛡️  SIEM System deployment completed!" -ForegroundColor Green
Write-Host "Monitor the logs with: docker-compose logs -f" -ForegroundColor Cyan
