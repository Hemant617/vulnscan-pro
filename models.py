"""
Database Models for VulnScan Pro
"""

from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()


class Scan(db.Model):
    """Scan model to store scan information"""
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(255), nullable=False)
    scan_type = db.Column(db.String(50), nullable=False)  # quick, standard, deep, full
    status = db.Column(db.String(50), default='pending')  # pending, running, completed, failed
    risk_score = db.Column(db.Integer, default=0)
    options = db.Column(db.Text)  # JSON string of scan options
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    completed_at = db.Column(db.DateTime)
    
    # Relationship
    vulnerabilities = db.relationship('Vulnerability', backref='scan', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<Scan {self.id}: {self.target}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'target': self.target,
            'scan_type': self.scan_type,
            'status': self.status,
            'risk_score': self.risk_score,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None
        }


class Vulnerability(db.Model):
    """Vulnerability model to store discovered vulnerabilities"""
    __tablename__ = 'vulnerabilities'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    title = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(50), nullable=False)  # critical, high, medium, low
    description = db.Column(db.Text)
    recommendation = db.Column(db.Text)
    cve = db.Column(db.String(50))  # CVE identifier if applicable
    port = db.Column(db.Integer)
    service = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    def __repr__(self):
        return f'<Vulnerability {self.id}: {self.title}>'
    
    def to_dict(self):
        return {
            'id': self.id,
            'scan_id': self.scan_id,
            'title': self.title,
            'severity': self.severity,
            'description': self.description,
            'recommendation': self.recommendation,
            'cve': self.cve,
            'port': self.port,
            'service': self.service,
            'created_at': self.created_at.isoformat() if self.created_at else None
        }
