from fastapi import APIRouter, Depends, HTTPException
import time
import secrets
from pydantic import BaseModel
# from typing import Optional
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.exceptions import InvalidSignature

from database.database import db

router = APIRouter()

CHALLENGE_EXPIRATION_TIME = 60
TOKEN_EXPIRATION_TIME = 60

@router.get("/auth/challenge")
async def create_challenge(device_id: str):

    device = db.devices.find_one({"_id": device_id})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    challenge = secrets.token_hex(16)
    expires_at = time.time() + CHALLENGE_EXPIRATION_TIME

    db.challenges.insert_one({
        "device_id": device_id,
        "challenge": challenge,
        "expires_at": expires_at
    })

    return {
        "device_id": device_id,
        "challenge": challenge,
        "expires_at": expires_at
    }

class ChallegeIn(BaseModel):
    device_id: str
    challenge: str
    expires_at: int
    signature: str


@router.post("/auth/verify")
async def verify_device_auth(body: ChallegeIn):
    challenge = body.json()

    # Validate the challenge
    if not (challenge["expires_at"] > time.time()):
        raise HTTPException(status_code=403, detail="Expired challenge")

    challenge_entry = db.challenges.find_one({
        "device_id": challenge["device_id"],
        "challenge": challenge["challenge"]
    })

    if not challenge_entry:
        raise HTTPException(status_code=403, detail="Invalid challenge")

    # Get the device public key
    device = db.devices.find_one({"_id": challenge["device_id"]}, {"public_key": 1})
    if not device or "public_key" not in device:
        raise HTTPException(status_code=404, detail="Device not found or without public key")

    public_key_pem = device["public_key"]
    public_key = serialization.load_pem_public_key(public_key_pem.encode())

    # Verify the signature
    try:
        public_key.verify(
            base64.b64decode(challenge["signature"]),
            challenge["challenge"].encode(),
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    except InvalidSignature:
        raise HTTPException(status_code=403, detail="Invalid signature")

    # Delete challenge
    db.challenges.delete_one({"_id": challenge_entry["_id"]})

    # Create the acess token
    token = secrets.token_hex(32)
    expires_at = time.time() + TOKEN_EXPIRATION_TIME

    filter = {"_id": challenge["device_id"]}
    data = {
        "access_token": {
            "token": token,
            "expires_at": expires_at
        }
    }
    result = db.devices.update_one(filter, {"$set": data})
    update_status = result._UpdateResult__raw_result["updatedExisting"]

    if not update_status:
        raise HTTPException(status_code=500, detail="Unable to create the access token")
        
    return {
        "device_id": challenge["device_id"],
        "access_token": token,
        "expires_at": expires_at
    }