#!/usr/bin/env python3
"""
SIEM Development Server
Runs a simplified version of the SIEM system for development/demo purposes
"""

import os
import sys
import json
import time
import threading
import subprocess
from datetime import datetime
from flask import Flask, render_template, jsonify, request
from werkzeug.serving import make_server

# Simple in-memory storage for demo
demo_data = {
    'alerts': [
        {
            'timestamp': datetime.now().isoformat(),
            'rule_name': 'SSH Brute Force Attack',
            'severity': 'high',
            'message': 'Multiple failed SSH attempts detected from 192.168.1.100',
            'matches': 15
        },
        {
            'timestamp': datetime.now().isoformat(),
            'rule_name': 'Privilege Escalation',
            'severity': 'medium',
            'message': 'Suspicious sudo activity from user john',
            'matches': 8
        },
        {
            'timestamp': datetime.now().isoformat(),
            'rule_name': 'Malicious IP Activity',
            'severity': 'critical',
            'message': 'Known malicious IP 203.0.113.50 detected',
            'matches': 3
        }
    ],
    'stats': {
        'total_events': 125847,
        'alerts_24h': 23,
        'recent_events_1h': 1547,
        'total_size_gb': 2.3,
        'indices_count': 12
    },
    'top_ips': [
        {'ip': '192.168.1.100', 'count': 45, 'country': 'United States', 'last_action': 'authentication_failure'},
        {'ip': '10.0.0.50', 'count': 32, 'country': 'Russia', 'last_action': 'privilege_escalation'},
        {'ip': '203.0.113.25', 'count': 28, 'country': 'China', 'last_action': 'web_attack'},
        {'ip': '172.16.0.15', 'count': 19, 'country': 'Germany', 'last_action': 'port_scan'}
    ],
    'auth_failures': {
        'total_failures': 156,
        'hourly_data': [
            {'key_as_string': '2024-01-01T10:00:00Z', 'doc_count': 12},
            {'key_as_string': '2024-01-01T11:00:00Z', 'doc_count': 18},
            {'key_as_string': '2024-01-01T12:00:00Z', 'doc_count': 25},
            {'key_as_string': '2024-01-01T13:00:00Z', 'doc_count': 31},
            {'key_as_string': '2024-01-01T14:00:00Z', 'doc_count': 22},
            {'key_as_string': '2024-01-01T15:00:00Z', 'doc_count': 15}
        ]
    },
    'blocked_ips': [
        {'ip': '192.168.1.100', 'timestamp': datetime.now().isoformat(), 'reason': 'SSH brute force', 'source': 'auto'},
        {'ip': '203.0.113.50', 'timestamp': datetime.now().isoformat(), 'reason': 'Known malicious IP', 'source': 'threat_intel'}
    ]
}

app = Flask(__name__)
app.secret_key = 'dev-secret-key'

@app.route('/')
def dashboard():
    return render_template('dashboard.html',
                         recent_alerts=demo_data['alerts'][:5],
                         stats=demo_data['stats'],
                         top_ips=demo_data['top_ips'][:5],
                         auth_failures=demo_data['auth_failures'])

@app.route('/alerts')
def alerts():
    page = int(request.args.get('page', 1))
    size = int(request.args.get('size', 10))
    severity = request.args.get('severity', 'all')
    
    filtered_alerts = demo_data['alerts']
    if severity != 'all':
        filtered_alerts = [a for a in demo_data['alerts'] if a['severity'] == severity]
    
    start = (page - 1) * size
    end = start + size
    page_alerts = filtered_alerts[start:end]
    
    pagination = {
        'current_page': page,
        'total_pages': max(1, (len(filtered_alerts) + size - 1) // size),
        'total_items': len(filtered_alerts),
        'has_prev': page > 1,
        'has_next': end < len(filtered_alerts),
        'prev_page': page - 1 if page > 1 else None,
        'next_page': page + 1 if end < len(filtered_alerts) else None
    }
    
    return render_template('alerts.html',
                         alerts=page_alerts,
                         pagination=pagination,
                         current_severity=severity)

@app.route('/search')
def search():
    query = request.args.get('q', '')
    time_range = request.args.get('time_range', '1h')
    
    # Mock search results
    results = {
        'hits': [
            {
                'timestamp': datetime.now().isoformat(),
                'index': 'siem-auth-2024.01.01',
                'source': {
                    'source.ip': '192.168.1.100',
                    'user.name': 'admin',
                    'event.action': 'authentication_failure',
                    'message': 'Failed password for admin from 192.168.1.100'
                }
            }
        ] if query else [],
        'total': 1 if query else 0
    }
    
    return render_template('search.html',
                         query=query,
                         time_range=time_range,
                         results=results)

@app.route('/blocked-ips')
def blocked_ips():
    return render_template('blocked_ips.html',
                         blocked_ips=demo_data['blocked_ips'])

@app.route('/api/block-ip', methods=['POST'])
def api_block_ip():
    data = request.get_json()
    ip = data.get('ip')
    reason = data.get('reason', 'Manual block')
    
    # Add to blocked IPs
    demo_data['blocked_ips'].append({
        'ip': ip,
        'timestamp': datetime.now().isoformat(),
        'reason': reason,
        'source': 'manual'
    })
    
    return jsonify({'message': f'Successfully blocked IP {ip}'})

@app.route('/api/unblock-ip', methods=['POST'])
def api_unblock_ip():
    data = request.get_json()
    ip = data.get('ip')
    
    # Remove from blocked IPs
    demo_data['blocked_ips'] = [b for b in demo_data['blocked_ips'] if b['ip'] != ip]
    
    return jsonify({'message': f'Successfully unblocked IP {ip}'})

@app.route('/api/stats')
def api_stats():
    return jsonify(demo_data['stats'])

@app.route('/health')
def health():
    return jsonify({
        'status': 'healthy',
        'elasticsearch': True,
        'redis': True,
        'timestamp': datetime.now().isoformat()
    })

def create_missing_templates():
    """Create missing HTML templates"""
    templates_dir = os.path.join(os.path.dirname(__file__), 'web', 'templates')
    
    # Create alerts.html
    alerts_html = '''{% extends "base.html" %}

{% block title %}Alerts - SIEM Dashboard{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col-12">
        <h1 class="h3 mb-0">Security Alerts</h1>
        <p class="text-muted">Real-time security alerts and incidents</p>
    </div>
</div>

<div class="row mb-4">
    <div class="col-md-6">
        <div class="btn-group" role="group">
            <a href="?severity=all" class="btn btn-outline-primary {% if current_severity == 'all' %}active{% endif %}">All</a>
            <a href="?severity=high" class="btn btn-outline-danger {% if current_severity == 'high' %}active{% endif %}">High</a>
            <a href="?severity=medium" class="btn btn-outline-warning {% if current_severity == 'medium' %}active{% endif %}">Medium</a>
            <a href="?severity=low" class="btn btn-outline-success {% if current_severity == 'low' %}active{% endif %}">Low</a>
        </div>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <i class="fas fa-exclamation-triangle me-2"></i>Alerts
    </div>
    <div class="card-body">
        {% if alerts %}
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Rule Name</th>
                            <th>Severity</th>
                            <th>Message</th>
                            <th>Matches</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for alert in alerts %}
                        <tr class="alert-{{ alert.severity }}">
                            <td>{{ alert.timestamp[:19] if alert.timestamp else 'N/A' }}</td>
                            <td>{{ alert.rule_name }}</td>
                            <td>
                                <span class="badge bg-{{ 'danger' if alert.severity == 'high' else 'warning' if alert.severity == 'medium' else 'success' }}">
                                    {{ alert.severity.upper() }}
                                </span>
                            </td>
                            <td>{{ alert.message }}</td>
                            <td>{{ alert.matches }}</td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        {% else %}
            <div class="text-center text-muted py-4">
                <i class="fas fa-shield-alt fa-3x mb-3"></i>
                <p>No alerts found</p>
            </div>
        {% endif %}
    </div>
</div>
{% endblock %}'''
    
    # Create search.html
    search_html = '''{% extends "base.html" %}

{% block title %}Search - SIEM Dashboard{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col-12">
        <h1 class="h3 mb-0">Log Search</h1>
        <p class="text-muted">Search and analyze security logs</p>
    </div>
</div>

<div class="card mb-4">
    <div class="card-body">
        <form method="GET">
            <div class="row">
                <div class="col-md-6">
                    <input type="text" name="q" class="form-control search-box" placeholder="Search logs..." value="{{ query }}">
                </div>
                <div class="col-md-3">
                    <select name="time_range" class="form-select">
                        <option value="15m" {% if time_range == '15m' %}selected{% endif %}>Last 15 minutes</option>
                        <option value="1h" {% if time_range == '1h' %}selected{% endif %}>Last hour</option>
                        <option value="4h" {% if time_range == '4h' %}selected{% endif %}>Last 4 hours</option>
                        <option value="24h" {% if time_range == '24h' %}selected{% endif %}>Last 24 hours</option>
                    </select>
                </div>
                <div class="col-md-3">
                    <button type="submit" class="btn btn-primary w-100">
                        <i class="fas fa-search me-1"></i>Search
                    </button>
                </div>
            </div>
        </form>
    </div>
</div>

{% if query %}
<div class="card">
    <div class="card-header">
        Search Results ({{ results.total }} found)
    </div>
    <div class="card-body">
        {% if results.hits %}
            {% for hit in results.hits %}
            <div class="border-bottom pb-3 mb-3">
                <div class="d-flex justify-content-between">
                    <strong>{{ hit.timestamp[:19] }}</strong>
                    <span class="badge bg-secondary">{{ hit.index }}</span>
                </div>
                <pre class="mt-2"><code>{{ hit.source | tojsonfilter }}</code></pre>
            </div>
            {% endfor %}
        {% else %}
            <div class="text-center text-muted py-4">
                <i class="fas fa-search fa-3x mb-3"></i>
                <p>No results found</p>
            </div>
        {% endif %}
    </div>
</div>
{% endif %}
{% endblock %}'''
    
    # Create blocked_ips.html
    blocked_ips_html = '''{% extends "base.html" %}

{% block title %}Blocked IPs - SIEM Dashboard{% endblock %}

{% block content %}
<div class="row mb-4">
    <div class="col-12">
        <h1 class="h3 mb-0">Blocked IP Addresses</h1>
        <p class="text-muted">Manage blocked IP addresses</p>
    </div>
</div>

<div class="card">
    <div class="card-header">
        <i class="fas fa-ban me-2"></i>Blocked IPs
    </div>
    <div class="card-body">
        {% if blocked_ips %}
            <div class="table-responsive">
                <table class="table table-hover">
                    <thead>
                        <tr>
                            <th>IP Address</th>
                            <th>Blocked At</th>
                            <th>Reason</th>
                            <th>Source</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for ip in blocked_ips %}
                        <tr>
                            <td><code>{{ ip.ip }}</code></td>
                            <td>{{ ip.timestamp[:19] if ip.timestamp else 'N/A' }}</td>
                            <td>{{ ip.reason }}</td>
                            <td>
                                <span class="badge bg-{{ 'warning' if ip.source == 'manual' else 'info' }}">
                                    {{ ip.source }}
                                </span>
                            </td>
                            <td>
                                <button class="btn btn-success btn-sm" onclick="unblockIP('{{ ip.ip }}')">
                                    <i class="fas fa-unlock"></i> Unblock
                                </button>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
        {% else %}
            <div class="text-center text-muted py-4">
                <i class="fas fa-shield-alt fa-3x mb-3"></i>
                <p>No blocked IPs</p>
            </div>
        {% endif %}
    </div>
</div>

<script>
function unblockIP(ip) {
    if (confirm('Are you sure you want to unblock ' + ip + '?')) {
        fetch('/api/unblock-ip', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ip: ip})
        })
        .then(response => response.json())
        .then(data => {
            alert(data.message);
            location.reload();
        });
    }
}
</script>
{% endblock %}'''
    
    # Write templates
    os.makedirs(templates_dir, exist_ok=True)
    
    with open(os.path.join(templates_dir, 'alerts.html'), 'w') as f:
        f.write(alerts_html)
    
    with open(os.path.join(templates_dir, 'search.html'), 'w') as f:
        f.write(search_html)
    
    with open(os.path.join(templates_dir, 'blocked_ips.html'), 'w') as f:
        f.write(blocked_ips_html)

def main():
    print("🛡️  Starting SIEM Development Server...")
    print("=" * 40)
    
    # Create missing templates
    create_missing_templates()
    
    # Change to web directory
    web_dir = os.path.join(os.path.dirname(__file__), 'web')
    if os.path.exists(web_dir):
        os.chdir(web_dir)
        sys.path.insert(0, web_dir)
    
    print("✅ SIEM Development Server Started!")
    print("")
    print("Access URLs:")
    print("• SIEM Dashboard: http://localhost:8080")
    print("")
    print("Features Available:")
    print("• Dashboard with demo data")
    print("• Alert management")
    print("• Log search simulation")
    print("• IP blocking/unblocking")
    print("")
    print("Press Ctrl+C to stop the server")
    print("")
    
    try:
        # Start Flask development server
        app.run(host='0.0.0.0', port=8080, debug=True, use_reloader=False)
    except KeyboardInterrupt:
        print("\n🛑 SIEM Development Server stopped")

if __name__ == '__main__':
    main()
