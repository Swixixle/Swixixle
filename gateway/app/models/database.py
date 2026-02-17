"""
Database models for ELI-Sentinel Gateway

Using SQLite for MVP with schema that maps cleanly to Postgres.
"""

from datetime import datetime
from typing import Optional
from sqlalchemy import create_engine, Column, String, DateTime, Boolean, Integer, Text, JSON, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker
import os

Base = declarative_base()


class Transaction(Base):
    """Transaction receipts (append-only)."""
    __tablename__ = 'transactions'
    
    transaction_id = Column(String(255), primary_key=True)
    gateway_timestamp_utc = Column(DateTime, nullable=False, index=True)
    environment = Column(String(50), nullable=False, index=True)
    client_id = Column(String(255), nullable=False, index=True)
    
    # Transaction details (stored as JSON)
    packet_data = Column(JSON, nullable=False)
    
    # HALO chain
    halo_chain = Column(JSON, nullable=False)
    
    # Signature
    signature_data = Column(JSON, nullable=False)
    
    # Policy reference
    policy_version_hash = Column(String(255), nullable=False, index=True)
    policy_change_ref = Column(String(255), nullable=True)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    
    def __repr__(self):
        return f"<Transaction(id={self.transaction_id}, env={self.environment})>"


class PolicyVersion(Base):
    """Policy versions (append-only, content-addressed)."""
    __tablename__ = 'policy_versions'
    
    policy_version_hash = Column(String(255), primary_key=True)  # sha256:...
    environment = Column(String(50), nullable=False, index=True)
    
    # Policy content
    policy_logic = Column(JSON, nullable=False)
    
    # Metadata (not included in hash)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_by = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    
    def __repr__(self):
        return f"<PolicyVersion(hash={self.policy_version_hash[:16]}...)>"


class PolicyChangeRequest(Base):
    """Policy change proposals (SOX-grade approval workflow)."""
    __tablename__ = 'policy_change_requests'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    
    # Proposal details
    environment = Column(String(50), nullable=False, index=True)
    proposed_policy_hash = Column(String(255), ForeignKey('policy_versions.policy_version_hash'), nullable=False)
    
    # Workflow
    status = Column(String(50), nullable=False, index=True)  # pending, approved, rejected
    proposer = Column(String(255), nullable=False, index=True)
    approver = Column(String(255), nullable=True, index=True)
    
    # Governance
    reason = Column(Text, nullable=False)
    ticket_ref = Column(String(255), nullable=True)  # Required for prod
    
    # Timestamps
    proposed_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    decided_at = Column(DateTime, nullable=True)
    
    # Relationship
    policy_version = relationship("PolicyVersion")
    
    def __repr__(self):
        return f"<PolicyChangeRequest(id={self.id}, status={self.status})>"


class ActivePolicyPointer(Base):
    """Pointer to active policy per environment."""
    __tablename__ = 'active_policy_pointers'
    
    environment = Column(String(50), primary_key=True)
    policy_version_hash = Column(String(255), ForeignKey('policy_versions.policy_version_hash'), nullable=False)
    activated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    activated_by = Column(String(255), nullable=False)
    change_request_id = Column(Integer, ForeignKey('policy_change_requests.id'), nullable=True)
    
    # Relationships
    policy_version = relationship("PolicyVersion")
    change_request = relationship("PolicyChangeRequest")
    
    def __repr__(self):
        return f"<ActivePolicyPointer(env={self.environment})>"


class APIKey(Base):
    """API keys for client authentication."""
    __tablename__ = 'api_keys'
    
    key_id = Column(String(255), primary_key=True)
    client_id = Column(String(255), nullable=False, index=True)
    
    key_hash = Column(String(255), nullable=False)  # bcrypt hash
    
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=True)
    
    def __repr__(self):
        return f"<APIKey(id={self.key_id}, client={self.client_id})>"


# Database setup
def get_engine(db_path: str = None):
    """Get database engine."""
    if db_path is None:
        db_dir = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(__file__))),
            'data'
        )
        os.makedirs(db_dir, exist_ok=True)
        db_path = os.path.join(db_dir, 'eli_sentinel.db')
    
    return create_engine(f'sqlite:///{db_path}', echo=False)


def init_db(engine=None):
    """Initialize database schema."""
    if engine is None:
        engine = get_engine()
    
    Base.metadata.create_all(engine)
    return engine


def get_session(engine=None):
    """Get database session."""
    if engine is None:
        engine = get_engine()
    
    Session = sessionmaker(bind=engine)
    return Session()
