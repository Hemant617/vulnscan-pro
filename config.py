"""
Configuration Settings
"""

import os

class Config:
    """Base configuration"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///vulnscan.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # ZAP Configuration
    ZAP_HOST = os.environ.get('ZAP_HOST', 'localhost')
    ZAP_PORT = int(os.environ.get('ZAP_PORT', 8080))
    ZAP_API_KEY = os.environ.get('ZAP_API_KEY')
    
    # Scan Configuration
    MAX_CONCURRENT_SCANS = int(os.environ.get('MAX_CONCURRENT_SCANS', 3))
    SCAN_TIMEOUT = int(os.environ.get('SCAN_TIMEOUT', 3600))  # 1 hour
    
    # Security
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class DevelopmentConfig(Config):
    """Development configuration"""
    DEBUG = True
    SESSION_COOKIE_SECURE = False


class ProductionConfig(Config):
    """Production configuration"""
    DEBUG = False


config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'default': DevelopmentConfig
}
