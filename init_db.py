"""
Initialize Database
Run this script to create the database tables
"""

from app import app, db

if __name__ == '__main__':
    with app.app_context():
        # Create all tables
        db.create_all()
        print("Database initialized successfully!")
        print("Tables created: scans, vulnerabilities")
