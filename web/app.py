#!/usr/bin/env python3
"""
SIEM Web Interface
Flask-based web application for managing and monitoring the SIEM system
"""

import os
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Any

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_cors import CORS
from elasticsearch import Elasticsearch
import redis
import requests

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'siem-secret-key-change-in-production')
CORS(app)

# Configuration
ELASTICSEARCH_URL = os.getenv('ELASTICSEARCH_URL', 'https://elasticsearch:9200')
ELASTICSEARCH_USERNAME = os.getenv('ELASTICSEARCH_USERNAME', 'elastic')
ELASTICSEARCH_PASSWORD = os.getenv('ELASTICSEARCH_PASSWORD', 'changeme')
REDIS_HOST = os.getenv('REDIS_HOST', 'redis')
REDIS_PASSWORD = os.getenv('REDIS_PASSWORD', 'siemredispass')

# Initialize connections
try:
    es = Elasticsearch(
        [ELASTICSEARCH_URL],
        basic_auth=(ELASTICSEARCH_USERNAME, ELASTICSEARCH_PASSWORD),
        verify_certs=False,
        ssl_show_warn=False
    )
    redis_client = redis.Redis(host=REDIS_HOST, password=REDIS_PASSWORD, decode_responses=True)
    logger.info("Connected to Elasticsearch and Redis")
except Exception as e:
    logger.error(f"Failed to connect to services: {e}")
    es = None
    redis_client = None

@app.route('/')
def dashboard():
    """Main dashboard"""
    try:
        # Get recent alerts
        recent_alerts = get_recent_alerts(limit=10)
        
        # Get system statistics
        stats = get_system_stats()
        
        # Get top source IPs
        top_ips = get_top_source_ips(limit=10)
        
        # Get authentication failures
        auth_failures = get_authentication_failures()
        
        return render_template('dashboard.html',
                             recent_alerts=recent_alerts,
                             stats=stats,
                             top_ips=top_ips,
                             auth_failures=auth_failures)
    except Exception as e:
        logger.error(f"Dashboard error: {e}")
        return render_template('error.html', error=str(e))

@app.route('/alerts')
def alerts():
    """Alerts page"""
    try:
        page = int(request.args.get('page', 1))
        size = int(request.args.get('size', 50))
        severity = request.args.get('severity', 'all')
        
        alerts_data = get_alerts(page=page, size=size, severity=severity)
        
        return render_template('alerts.html',
                             alerts=alerts_data['alerts'],
                             pagination=alerts_data['pagination'],
                             current_severity=severity)
    except Exception as e:
        logger.error(f"Alerts page error: {e}")
        return render_template('error.html', error=str(e))

@app.route('/search')
def search():
    """Search page"""
    try:
        query = request.args.get('q', '')
        time_range = request.args.get('time_range', '1h')
        index_pattern = request.args.get('index', 'siem-*')
        
        if query:
            results = search_logs(query, time_range, index_pattern)
        else:
            results = {'hits': [], 'total': 0}
        
        return render_template('search.html',
                             query=query,
                             time_range=time_range,
                             index_pattern=index_pattern,
                             results=results)
    except Exception as e:
        logger.error(f"Search page error: {e}")
        return render_template('error.html', error=str(e))

@app.route('/blocked-ips')
def blocked_ips():
    """Blocked IPs management page"""
    try:
        blocked_ips_data = get_blocked_ips()
        return render_template('blocked_ips.html', blocked_ips=blocked_ips_data)
    except Exception as e:
        logger.error(f"Blocked IPs page error: {e}")
        return render_template('error.html', error=str(e))

@app.route('/api/block-ip', methods=['POST'])
def api_block_ip():
    """API endpoint to block an IP"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        reason = data.get('reason', 'Manual block via web interface')
        
        if not ip:
            return jsonify({'error': 'IP address is required'}), 400
        
        # Call IP blocker script
        result = block_ip_address(ip, reason)
        
        if result['success']:
            return jsonify({'message': f'Successfully blocked IP {ip}'}), 200
        else:
            return jsonify({'error': result['error']}), 500
            
    except Exception as e:
        logger.error(f"Block IP API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/unblock-ip', methods=['POST'])
def api_unblock_ip():
    """API endpoint to unblock an IP"""
    try:
        data = request.get_json()
        ip = data.get('ip')
        
        if not ip:
            return jsonify({'error': 'IP address is required'}), 400
        
        # Call IP blocker script
        result = unblock_ip_address(ip)
        
        if result['success']:
            return jsonify({'message': f'Successfully unblocked IP {ip}'}), 200
        else:
            return jsonify({'error': result['error']}), 500
            
    except Exception as e:
        logger.error(f"Unblock IP API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats')
def api_stats():
    """API endpoint for system statistics"""
    try:
        stats = get_system_stats()
        return jsonify(stats)
    except Exception as e:
        logger.error(f"Stats API error: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/health')
def health():
    """Health check endpoint"""
    try:
        # Check Elasticsearch connection
        es_health = es.ping() if es else False
        
        # Check Redis connection
        redis_health = redis_client.ping() if redis_client else False
        
        status = 'healthy' if es_health and redis_health else 'unhealthy'
        
        return jsonify({
            'status': status,
            'elasticsearch': es_health,
            'redis': redis_health,
            'timestamp': datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

def get_recent_alerts(limit: int = 10) -> List[Dict]:
    """Get recent alerts from Elasticsearch"""
    try:
        if not es:
            return []
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "alert"}},
                        {"range": {"@timestamp": {"gte": "now-24h"}}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": limit
        }
        
        response = es.search(index="elastalert_status", body=query)
        alerts = []
        
        for hit in response['hits']['hits']:
            source = hit['_source']
            alerts.append({
                'timestamp': source.get('@timestamp'),
                'rule_name': source.get('rule_name', 'Unknown'),
                'severity': source.get('alert_severity', 'medium'),
                'message': source.get('alert_text', ''),
                'matches': source.get('num_matches', 1)
            })
        
        return alerts
    except Exception as e:
        logger.error(f"Error getting recent alerts: {e}")
        return []

def get_system_stats() -> Dict:
    """Get system statistics"""
    try:
        if not es:
            return {}
        
        # Get index statistics
        indices_stats = es.indices.stats(index="siem-*")
        total_docs = indices_stats['_all']['total']['docs']['count']
        total_size = indices_stats['_all']['total']['store']['size_in_bytes']
        
        # Get recent events count
        recent_query = {
            "query": {
                "range": {"@timestamp": {"gte": "now-1h"}}
            }
        }
        recent_response = es.count(index="siem-*", body=recent_query)
        recent_events = recent_response['count']
        
        # Get alerts count
        alerts_query = {
            "query": {
                "range": {"@timestamp": {"gte": "now-24h"}}
            }
        }
        alerts_response = es.count(index="elastalert_status", body=alerts_query)
        alerts_count = alerts_response['count']
        
        return {
            'total_events': total_docs,
            'total_size_gb': round(total_size / (1024**3), 2),
            'recent_events_1h': recent_events,
            'alerts_24h': alerts_count,
            'indices_count': len(indices_stats['indices'])
        }
    except Exception as e:
        logger.error(f"Error getting system stats: {e}")
        return {}

def get_top_source_ips(limit: int = 10) -> List[Dict]:
    """Get top source IPs by event count"""
    try:
        if not es:
            return []
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"exists": {"field": "source.ip"}},
                        {"range": {"@timestamp": {"gte": "now-24h"}}}
                    ]
                }
            },
            "aggs": {
                "top_ips": {
                    "terms": {
                        "field": "source.ip.keyword",
                        "size": limit
                    },
                    "aggs": {
                        "latest_event": {
                            "top_hits": {
                                "size": 1,
                                "sort": [{"@timestamp": {"order": "desc"}}],
                                "_source": ["source.geo", "event.action"]
                            }
                        }
                    }
                }
            },
            "size": 0
        }
        
        response = es.search(index="siem-*", body=query)
        top_ips = []
        
        for bucket in response['aggregations']['top_ips']['buckets']:
            ip = bucket['key']
            count = bucket['doc_count']
            latest = bucket['latest_event']['hits']['hits'][0]['_source']
            
            top_ips.append({
                'ip': ip,
                'count': count,
                'country': latest.get('source', {}).get('geo', {}).get('country_name', 'Unknown'),
                'last_action': latest.get('event', {}).get('action', 'Unknown')
            })
        
        return top_ips
    except Exception as e:
        logger.error(f"Error getting top source IPs: {e}")
        return []

def get_authentication_failures() -> Dict:
    """Get authentication failure statistics"""
    try:
        if not es:
            return {}
        
        query = {
            "query": {
                "bool": {
                    "must": [
                        {"terms": {"event.action": ["authentication_failure", "logon_failure"]}},
                        {"range": {"@timestamp": {"gte": "now-24h"}}}
                    ]
                }
            },
            "aggs": {
                "failures_over_time": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "1h"
                    }
                },
                "top_failed_users": {
                    "terms": {
                        "field": "user.name.keyword",
                        "size": 10
                    }
                }
            },
            "size": 0
        }
        
        response = es.search(index="siem-*", body=query)
        
        return {
            'total_failures': response['hits']['total']['value'],
            'hourly_data': response['aggregations']['failures_over_time']['buckets'],
            'top_failed_users': response['aggregations']['top_failed_users']['buckets']
        }
    except Exception as e:
        logger.error(f"Error getting authentication failures: {e}")
        return {}

def get_alerts(page: int = 1, size: int = 50, severity: str = 'all') -> Dict:
    """Get paginated alerts"""
    try:
        if not es:
            return {'alerts': [], 'pagination': {}}
        
        from_offset = (page - 1) * size
        
        query = {
            "query": {
                "bool": {
                    "must": [{"exists": {"field": "alert"}}]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "from": from_offset,
            "size": size
        }
        
        if severity != 'all':
            query['query']['bool']['must'].append({
                "term": {"alert_severity": severity}
            })
        
        response = es.search(index="elastalert_status", body=query)
        alerts = []
        
        for hit in response['hits']['hits']:
            source = hit['_source']
            alerts.append({
                'id': hit['_id'],
                'timestamp': source.get('@timestamp'),
                'rule_name': source.get('rule_name', 'Unknown'),
                'severity': source.get('alert_severity', 'medium'),
                'message': source.get('alert_text', ''),
                'matches': source.get('num_matches', 1)
            })
        
        total = response['hits']['total']['value']
        total_pages = (total + size - 1) // size
        
        pagination = {
            'current_page': page,
            'total_pages': total_pages,
            'total_items': total,
            'has_prev': page > 1,
            'has_next': page < total_pages,
            'prev_page': page - 1 if page > 1 else None,
            'next_page': page + 1 if page < total_pages else None
        }
        
        return {'alerts': alerts, 'pagination': pagination}
    except Exception as e:
        logger.error(f"Error getting alerts: {e}")
        return {'alerts': [], 'pagination': {}}

def search_logs(query: str, time_range: str, index_pattern: str) -> Dict:
    """Search logs in Elasticsearch"""
    try:
        if not es:
            return {'hits': [], 'total': 0}
        
        # Convert time range to Elasticsearch format
        time_ranges = {
            '15m': 'now-15m',
            '1h': 'now-1h',
            '4h': 'now-4h',
            '12h': 'now-12h',
            '24h': 'now-24h',
            '7d': 'now-7d'
        }
        
        gte_time = time_ranges.get(time_range, 'now-1h')
        
        search_query = {
            "query": {
                "bool": {
                    "must": [
                        {"query_string": {"query": query}},
                        {"range": {"@timestamp": {"gte": gte_time}}}
                    ]
                }
            },
            "sort": [{"@timestamp": {"order": "desc"}}],
            "size": 100
        }
        
        response = es.search(index=index_pattern, body=search_query)
        
        hits = []
        for hit in response['hits']['hits']:
            hits.append({
                'timestamp': hit['_source'].get('@timestamp'),
                'index': hit['_index'],
                'source': hit['_source']
            })
        
        return {
            'hits': hits,
            'total': response['hits']['total']['value']
        }
    except Exception as e:
        logger.error(f"Error searching logs: {e}")
        return {'hits': [], 'total': 0}

def get_blocked_ips() -> List[Dict]:
    """Get list of blocked IPs"""
    try:
        # This would typically read from the IP blocker script's data
        # For now, return cached data from Redis
        blocked_ips = []
        
        if redis_client:
            keys = redis_client.keys("blocked_ip:*")
            for key in keys:
                ip_data = redis_client.hgetall(key)
                if ip_data:
                    blocked_ips.append({
                        'ip': key.replace('blocked_ip:', ''),
                        'timestamp': ip_data.get('timestamp'),
                        'reason': ip_data.get('reason'),
                        'source': ip_data.get('source', 'manual')
                    })
        
        return sorted(blocked_ips, key=lambda x: x['timestamp'], reverse=True)
    except Exception as e:
        logger.error(f"Error getting blocked IPs: {e}")
        return []

def block_ip_address(ip: str, reason: str) -> Dict:
    """Block an IP address"""
    try:
        # Call the IP blocker script
        import subprocess
        result = subprocess.run([
            'python3', '/app/scripts/ip_blocker.py', 'block', ip, reason
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            # Cache in Redis
            if redis_client:
                redis_client.hset(f"blocked_ip:{ip}", mapping={
                    'timestamp': datetime.now().isoformat(),
                    'reason': reason,
                    'source': 'web_interface'
                })
            
            return {'success': True}
        else:
            return {'success': False, 'error': result.stderr}
    except Exception as e:
        logger.error(f"Error blocking IP {ip}: {e}")
        return {'success': False, 'error': str(e)}

def unblock_ip_address(ip: str) -> Dict:
    """Unblock an IP address"""
    try:
        # Call the IP blocker script
        import subprocess
        result = subprocess.run([
            'python3', '/app/scripts/ip_blocker.py', 'unblock', ip
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            # Remove from Redis cache
            if redis_client:
                redis_client.delete(f"blocked_ip:{ip}")
            
            return {'success': True}
        else:
            return {'success': False, 'error': result.stderr}
    except Exception as e:
        logger.error(f"Error unblocking IP {ip}: {e}")
        return {'success': False, 'error': str(e)}

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=False)
