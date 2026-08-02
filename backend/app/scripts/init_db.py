"""Database initialization script for seeding initial data."""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from sqlalchemy.orm import Session
from app.db.database import SessionLocal, engine, Base
from app.models.user import User, UserRole
from app.models.organization import Organization
from app.core.security import get_password_hash


def init_db():
    """Initialize database with default data."""
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    db = SessionLocal()
    try:
        # Check if admin already exists
        admin = db.query(User).filter(User.username == "admin").first()
        if admin:
            print("Admin user already exists.")
            return
        
        # Create default organization
        default_org = Organization(
            name="Default Organization",
            description="Default organization for initial setup",
            domain="example.com",
            industry="Technology"
        )
        db.add(default_org)
        db.flush()
        
        # Create admin user
        admin_user = User(
            email="admin@judahsecurity.com",
            username="admin",
            hashed_password=get_password_hash("admin123"),
            full_name="System Administrator",
            role=UserRole.ADMIN,
            is_superuser=True,
            organization_id=default_org.id
        )
        db.add(admin_user)
        
        # Create analyst user
        analyst_user = User(
            email="analyst@judahsecurity.com",
            username="analyst",
            hashed_password=get_password_hash("analyst123"),
            full_name="Security Analyst",
            role=UserRole.ANALYST,
            organization_id=default_org.id
        )
        db.add(analyst_user)
        
        # Create viewer user
        viewer_user = User(
            email="viewer@judahsecurity.com",
            username="viewer",
            hashed_password=get_password_hash("viewer123"),
            full_name="Read Only User",
            role=UserRole.VIEWER,
            organization_id=default_org.id
        )
        db.add(viewer_user)
        
        db.commit()
        
        print("Database initialized successfully!")
        print("\nDefault users created:")
        print("  Admin:   username='admin', password='admin123'")
        print("  Analyst: username='analyst', password='analyst123'")
        print("  Viewer:  username='viewer', password='viewer123'")
        print("\nPlease change these passwords after first login!")
        
    except Exception as e:
        print(f"Error initializing database: {e}")
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    print("Initializing database...")
    init_db()






