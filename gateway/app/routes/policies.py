"""
Policy management routes
"""

from datetime import datetime
from typing import Optional, List
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from gateway.app.models.database import (
    get_session, PolicyVersion, PolicyChangeRequest, ActivePolicyPointer
)
from gateway.app.services.policy import compute_policy_hash, validate_policy_logic

router = APIRouter(prefix="/v1/policies", tags=["policies"])


# Pydantic models for requests/responses
class PolicyLogic(BaseModel):
    """Policy logic structure."""
    version: str
    rules: List[dict]
    
    class Config:
        schema_extra = {
            "example": {
                "version": "1.0",
                "rules": [
                    {
                        "condition": {"client_id": "allowed_client"},
                        "action": "approve"
                    }
                ]
            }
        }


class PolicyProposalRequest(BaseModel):
    """Request to propose a policy change."""
    environment: str = Field(..., description="Target environment (dev, staging, production)")
    policy_logic: dict = Field(..., description="Policy logic (will be hashed)")
    proposer: str = Field(..., description="Proposer username/ID")
    reason: str = Field(..., description="Reason for change")
    ticket_ref: Optional[str] = Field(None, description="Ticket reference (required for production)")
    description: Optional[str] = Field(None, description="Human-readable description")


class PolicyApprovalRequest(BaseModel):
    """Request to approve a policy change."""
    approver: str = Field(..., description="Approver username/ID")


class PolicyRejectionRequest(BaseModel):
    """Request to reject a policy change."""
    approver: str = Field(..., description="Approver username/ID (rejector)")


def get_db():
    """Dependency to get database session."""
    db = get_session()
    try:
        yield db
    finally:
        db.close()


@router.post("/proposals")
async def create_policy_proposal(
    request: PolicyProposalRequest,
    db: Session = Depends(get_db)
):
    """
    Propose a new policy change.
    
    Creates a policy version and change request for approval.
    """
    # Validate policy logic
    validation = validate_policy_logic(request.policy_logic)
    if not validation["valid"]:
        raise HTTPException(status_code=400, detail={
            "error": "Invalid policy logic",
            "validation_errors": validation["errors"]
        })
    
    # Check ticket requirement for production
    if request.environment == "production" and not request.ticket_ref:
        raise HTTPException(
            status_code=400,
            detail="ticket_ref is required for production environment"
        )
    
    # Compute policy hash
    policy_hash = compute_policy_hash(request.policy_logic)
    
    # Create or get policy version
    policy_version = db.query(PolicyVersion).filter_by(
        policy_version_hash=policy_hash
    ).first()
    
    if not policy_version:
        policy_version = PolicyVersion(
            policy_version_hash=policy_hash,
            environment=request.environment,
            policy_logic=request.policy_logic,
            created_by=request.proposer,
            description=request.description
        )
        db.add(policy_version)
        db.commit()
    
    # Create change request
    change_request = PolicyChangeRequest(
        environment=request.environment,
        proposed_policy_hash=policy_hash,
        status="pending",
        proposer=request.proposer,
        reason=request.reason,
        ticket_ref=request.ticket_ref
    )
    
    db.add(change_request)
    db.commit()
    db.refresh(change_request)
    
    return {
        "proposal_id": change_request.id,
        "policy_version_hash": policy_hash,
        "environment": request.environment,
        "status": "pending",
        "proposed_at": change_request.proposed_at.isoformat()
    }


@router.post("/proposals/{proposal_id}/approve")
async def approve_policy_proposal(
    proposal_id: int,
    request: PolicyApprovalRequest,
    db: Session = Depends(get_db)
):
    """
    Approve a policy change proposal.
    
    Enforces:
    - Proposer != Approver for production
    - Activates the policy for the environment
    """
    # Get change request
    change_request = db.query(PolicyChangeRequest).filter_by(id=proposal_id).first()
    
    if not change_request:
        raise HTTPException(status_code=404, detail="Proposal not found")
    
    if change_request.status != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Proposal already {change_request.status}"
        )
    
    # Enforce proposer != approver for production
    if change_request.environment == "production":
        if change_request.proposer == request.approver:
            raise HTTPException(
                status_code=403,
                detail="Proposer cannot approve their own proposal in production"
            )
    
    # Update change request
    change_request.status = "approved"
    change_request.approver = request.approver
    change_request.decided_at = datetime.utcnow()
    
    # Activate policy
    active_pointer = db.query(ActivePolicyPointer).filter_by(
        environment=change_request.environment
    ).first()
    
    if active_pointer:
        # Update existing pointer
        active_pointer.policy_version_hash = change_request.proposed_policy_hash
        active_pointer.activated_at = datetime.utcnow()
        active_pointer.activated_by = request.approver
        active_pointer.change_request_id = proposal_id
    else:
        # Create new pointer
        active_pointer = ActivePolicyPointer(
            environment=change_request.environment,
            policy_version_hash=change_request.proposed_policy_hash,
            activated_by=request.approver,
            change_request_id=proposal_id
        )
        db.add(active_pointer)
    
    db.commit()
    
    return {
        "proposal_id": proposal_id,
        "status": "approved",
        "policy_version_hash": change_request.proposed_policy_hash,
        "approver": request.approver,
        "activated_at": active_pointer.activated_at.isoformat()
    }


@router.post("/proposals/{proposal_id}/reject")
async def reject_policy_proposal(
    proposal_id: int,
    request: PolicyRejectionRequest,
    db: Session = Depends(get_db)
):
    """Reject a policy change proposal."""
    # Get change request
    change_request = db.query(PolicyChangeRequest).filter_by(id=proposal_id).first()
    
    if not change_request:
        raise HTTPException(status_code=404, detail="Proposal not found")
    
    if change_request.status != "pending":
        raise HTTPException(
            status_code=400,
            detail=f"Proposal already {change_request.status}"
        )
    
    # Update change request
    change_request.status = "rejected"
    change_request.approver = request.approver
    change_request.decided_at = datetime.utcnow()
    
    db.commit()
    
    return {
        "proposal_id": proposal_id,
        "status": "rejected",
        "rejector": request.approver,
        "rejected_at": change_request.decided_at.isoformat()
    }


@router.get("/active")
async def get_active_policy(
    environment: str,
    db: Session = Depends(get_db)
):
    """Get the active policy for an environment."""
    active_pointer = db.query(ActivePolicyPointer).filter_by(
        environment=environment
    ).first()
    
    if not active_pointer:
        raise HTTPException(
            status_code=404,
            detail=f"No active policy for environment: {environment}"
        )
    
    policy_version = active_pointer.policy_version
    
    return {
        "environment": environment,
        "policy_version_hash": policy_version.policy_version_hash,
        "policy_logic": policy_version.policy_logic,
        "activated_at": active_pointer.activated_at.isoformat(),
        "activated_by": active_pointer.activated_by
    }


@router.get("/changes")
async def list_policy_changes(
    environment: Optional[str] = None,
    status: Optional[str] = None,
    db: Session = Depends(get_db)
):
    """List policy change requests."""
    query = db.query(PolicyChangeRequest)
    
    if environment:
        query = query.filter_by(environment=environment)
    
    if status:
        query = query.filter_by(status=status)
    
    changes = query.order_by(PolicyChangeRequest.proposed_at.desc()).all()
    
    return {
        "changes": [
            {
                "proposal_id": change.id,
                "environment": change.environment,
                "policy_version_hash": change.proposed_policy_hash,
                "status": change.status,
                "proposer": change.proposer,
                "approver": change.approver,
                "reason": change.reason,
                "ticket_ref": change.ticket_ref,
                "proposed_at": change.proposed_at.isoformat(),
                "decided_at": change.decided_at.isoformat() if change.decided_at else None
            }
            for change in changes
        ]
    }
