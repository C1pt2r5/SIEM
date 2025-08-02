#!/bin/bash

# SIEM Certificate Setup Script
# Creates self-signed certificates for secure communication

set -e

echo "Setting up certificates for SIEM system..."

# Create certificate directories
mkdir -p certs/{ca,elasticsearch,kibana,logstash,filebeat,winlogbeat}

# Certificate configuration
CERT_DIR="certs"
CA_DIR="$CERT_DIR/ca"
ES_DIR="$CERT_DIR/elasticsearch"
KIBANA_DIR="$CERT_DIR/kibana"
LOGSTASH_DIR="$CERT_DIR/logstash"
FILEBEAT_DIR="$CERT_DIR/filebeat"
WINLOGBEAT_DIR="$CERT_DIR/winlogbeat"

# Certificate Authority
echo "Creating Certificate Authority..."
openssl genrsa -out $CA_DIR/ca.key 4096
openssl req -new -x509 -days 3650 -key $CA_DIR/ca.key -out $CA_DIR/ca.crt -subj "/C=US/ST=CA/L=San Francisco/O=SIEM/OU=Security/CN=SIEM-CA"

# Elasticsearch certificates
echo "Creating Elasticsearch certificates..."
openssl genrsa -out $ES_DIR/elasticsearch.key 2048
openssl req -new -key $ES_DIR/elasticsearch.key -out $ES_DIR/elasticsearch.csr -subj "/C=US/ST=CA/L=San Francisco/O=SIEM/OU=Security/CN=elasticsearch"

# Create SAN config for Elasticsearch
cat > $ES_DIR/elasticsearch.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = SIEM
OU = Security
CN = elasticsearch

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = elasticsearch
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = 172.20.0.2
EOF

openssl x509 -req -in $ES_DIR/elasticsearch.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key -CAcreateserial -out $ES_DIR/elasticsearch.crt -days 365 -extensions v3_req -extfile $ES_DIR/elasticsearch.conf

# Kibana certificates
echo "Creating Kibana certificates..."
openssl genrsa -out $KIBANA_DIR/kibana.key 2048
openssl req -new -key $KIBANA_DIR/kibana.key -out $KIBANA_DIR/kibana.csr -subj "/C=US/ST=CA/L=San Francisco/O=SIEM/OU=Security/CN=kibana"

cat > $KIBANA_DIR/kibana.conf <<EOF
[req]
distinguished_name = req_distinguished_name
req_extensions = v3_req
prompt = no

[req_distinguished_name]
C = US
ST = CA
L = San Francisco
O = SIEM
OU = Security
CN = kibana

[v3_req]
keyUsage = keyEncipherment, dataEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = kibana
DNS.2 = localhost
IP.1 = 127.0.0.1
IP.2 = 172.20.0.3
EOF

openssl x509 -req -in $KIBANA_DIR/kibana.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key -CAcreateserial -out $KIBANA_DIR/kibana.crt -days 365 -extensions v3_req -extfile $KIBANA_DIR/kibana.conf

# Logstash certificates
echo "Creating Logstash certificates..."
openssl genrsa -out $LOGSTASH_DIR/logstash.key 2048
openssl req -new -key $LOGSTASH_DIR/logstash.key -out $LOGSTASH_DIR/logstash.csr -subj "/C=US/ST=CA/L=San Francisco/O=SIEM/OU=Security/CN=logstash"
openssl x509 -req -in $LOGSTASH_DIR/logstash.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key -CAcreateserial -out $LOGSTASH_DIR/logstash.crt -days 365

# Filebeat certificates
echo "Creating Filebeat certificates..."
openssl genrsa -out $FILEBEAT_DIR/filebeat.key 2048
openssl req -new -key $FILEBEAT_DIR/filebeat.key -out $FILEBEAT_DIR/filebeat.csr -subj "/C=US/ST=CA/L=San Francisco/O=SIEM/OU=Security/CN=filebeat"
openssl x509 -req -in $FILEBEAT_DIR/filebeat.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key -CAcreateserial -out $FILEBEAT_DIR/filebeat.crt -days 365

# Winlogbeat certificates
echo "Creating Winlogbeat certificates..."
openssl genrsa -out $WINLOGBEAT_DIR/winlogbeat.key 2048
openssl req -new -key $WINLOGBEAT_DIR/winlogbeat.key -out $WINLOGBEAT_DIR/winlogbeat.csr -subj "/C=US/ST=CA/L=San Francisco/O=SIEM/OU=Security/CN=winlogbeat"
openssl x509 -req -in $WINLOGBEAT_DIR/winlogbeat.csr -CA $CA_DIR/ca.crt -CAkey $CA_DIR/ca.key -CAcreateserial -out $WINLOGBEAT_DIR/winlogbeat.crt -days 365

# Set proper permissions
echo "Setting certificate permissions..."
find $CERT_DIR -name "*.key" -exec chmod 600 {} \;
find $CERT_DIR -name "*.crt" -exec chmod 644 {} \;
find $CERT_DIR -name "*.csr" -exec rm {} \;
find $CERT_DIR -name "*.conf" -exec rm {} \;

# Create certificate bundle for easy distribution
echo "Creating certificate bundle..."
tar -czf siem-certificates.tar.gz certs/

echo "Certificate setup completed!"
echo "Certificates are located in the 'certs' directory"
echo "Certificate bundle: siem-certificates.tar.gz"
echo ""
echo "Next steps:"
echo "1. Copy certificates to target systems"
echo "2. Update agent configurations with certificate paths"
echo "3. Start the SIEM system with: docker-compose up -d"
