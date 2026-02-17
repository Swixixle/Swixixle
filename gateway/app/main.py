"""
FastAPI main application for ELI-Sentinel Gateway
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import JSONResponse
from gateway.app.services.signer import get_signer
from gateway.app.routes.policies import router as policies_router
from gateway.app.routes.transactions import router as transactions_router
from gateway.app.models.database import init_db

# Initialize database
init_db()

app = FastAPI(
    title="ELI-Sentinel Gateway",
    description="AI Governance Gateway with tamper-evident transaction receipts",
    version="0.1.0"
)

# Include routers
app.include_router(policies_router)
app.include_router(transactions_router)


@app.get("/")
async def root():
    """Health check endpoint."""
    return {
        "service": "ELI-Sentinel Gateway",
        "status": "operational",
        "version": "0.1.0"
    }


@app.get("/v1/keys")
async def list_keys():
    """
    List all active signing keys.
    
    Returns:
        List of key metadata
    """
    signer = get_signer()
    key_id = signer.get_key_id()
    
    return {
        "keys": [
            {
                "kid": key_id,
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256"
            }
        ]
    }


@app.get("/v1/keys/{key_id}")
async def get_key(key_id: str):
    """
    Get a specific public key as JWK.
    
    Args:
        key_id: Key identifier
        
    Returns:
        JWK for the specified key
    """
    signer = get_signer()
    current_key_id = signer.get_key_id()
    
    if key_id != current_key_id:
        raise HTTPException(
            status_code=404,
            detail=f"Key not found: {key_id}"
        )
    
    return signer.get_public_jwk(key_id)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
