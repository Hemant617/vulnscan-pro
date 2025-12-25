#!/usr/bin/env python3
"""
VulnScan Pro - Main Flask Application
Automated Vulnerability Scanner for Small Businesses
"""

from flask import Flask, render_template, request, jsonify, session
from datetime import datetime
import json
import threading
from models import db, Scan, Vulnerability
from scanner import VulnerabilityScanner
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///vulnscan.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize database
db.init_app(app)

# Create tables
with app.app_context():
    db.create_all()

# Store active scans
active_scans = {}


@app.route('/')
def index():
    """Dashboard home page"""
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(10).all()
    
    # Calculate statistics
    total_scans = Scan.query.count()
    total_vulns = Vulnerability.query.count()
    critical_vulns = Vulnerability.query.filter_by(severity='critical').count()
    
    stats = {
        'total_scans': total_scans,
        'total_vulnerabilities': total_vulns,
        'critical_vulnerabilities': critical_vulns,
        'recent_scans': recent_scans
    }
    
    return render_template('index.html', stats=stats)


@app.route('/scan')
def scan_page():
    """Scan configuration page"""
    return render_template('scan.html')


@app.route('/api/scan/start', methods=['POST'])
def start_scan():
    """Start a new vulnerability scan"""
    data = request.get_json()
    
    target = data.get('target')
    scan_type = data.get('scan_type', 'standard')
    options = data.get('options', {})
    
    if not target:
        return jsonify({'error': 'Target is required'}), 400
    
    # Create scan record
    scan = Scan(
        target=target,
        scan_type=scan_type,
        status='running',
        options=json.dumps(options)
    )
    db.session.add(scan)
    db.session.commit()
    
    # Start scan in background thread
    scanner = VulnerabilityScanner(scan.id, target, scan_type, options)
    thread = threading.Thread(target=scanner.run_scan)
    thread.daemon = True
    thread.start()
    
    active_scans[scan.id] = scanner
    
    return jsonify({
        'success': True,
        'scan_id': scan.id,
        'message': 'Scan started successfully'
    })


@app.route('/api/scan/<int:scan_id>/status')
def scan_status(scan_id):
    """Get scan status and progress"""
    scan = Scan.query.get_or_404(scan_id)
    
    progress = 0
    current_task = 'Initializing...'
    
    if scan_id in active_scans:
        scanner = active_scans[scan_id]
        progress = scanner.progress
        current_task = scanner.current_task
    
    return jsonify({
        'scan_id': scan.id,
        'status': scan.status,
        'progress': progress,
        'current_task': current_task,
        'started_at': scan.created_at.isoformat() if scan.created_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
    })


@app.route('/api/scan/<int:scan_id>/results')
def scan_results(scan_id):
    """Get scan results"""
    scan = Scan.query.get_or_404(scan_id)
    vulnerabilities = Vulnerability.query.filter_by(scan_id=scan_id).all()
    
    # Count by severity
    severity_counts = {
        'critical': 0,
        'high': 0,
        'medium': 0,
        'low': 0
    }
    
    vuln_list = []
    for vuln in vulnerabilities:
        severity_counts[vuln.severity] += 1
        vuln_list.append({
            'id': vuln.id,
            'title': vuln.title,
            'severity': vuln.severity,
            'description': vuln.description,
            'recommendation': vuln.recommendation,
            'cve': vuln.cve,
            'port': vuln.port,
            'service': vuln.service
        })
    
    return jsonify({
        'scan_id': scan.id,
        'target': scan.target,
        'scan_type': scan.scan_type,
        'status': scan.status,
        'risk_score': scan.risk_score,
        'severity_counts': severity_counts,
        'vulnerabilities': vuln_list,
        'created_at': scan.created_at.isoformat() if scan.created_at else None,
        'completed_at': scan.completed_at.isoformat() if scan.completed_at else None
    })


@app.route('/results/<int:scan_id>')
def results_page(scan_id):
    """Display scan results page"""
    scan = Scan.query.get_or_404(scan_id)
    return render_template('results.html', scan=scan)


@app.route('/api/scans')
def list_scans():
    """List all scans"""
    page = request.args.get('page', 1, type=int)
    per_page = request.args.get('per_page', 20, type=int)
    
    scans = Scan.query.order_by(Scan.created_at.desc()).paginate(
        page=page, per_page=per_page, error_out=False
    )
    
    return jsonify({
        'scans': [{
            'id': scan.id,
            'target': scan.target,
            'scan_type': scan.scan_type,
            'status': scan.status,
            'risk_score': scan.risk_score,
            'created_at': scan.created_at.isoformat() if scan.created_at else None
        } for scan in scans.items],
        'total': scans.total,
        'pages': scans.pages,
        'current_page': page
    })


@app.route('/api/scan/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """Delete a scan and its vulnerabilities"""
    scan = Scan.query.get_or_404(scan_id)
    
    # Delete associated vulnerabilities
    Vulnerability.query.filter_by(scan_id=scan_id).delete()
    
    # Delete scan
    db.session.delete(scan)
    db.session.commit()
    
    return jsonify({'success': True, 'message': 'Scan deleted successfully'})


@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404


@app.errorhandler(500)
def internal_error(error):
    db.session.rollback()
    return jsonify({'error': 'Internal server error'}), 500


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
