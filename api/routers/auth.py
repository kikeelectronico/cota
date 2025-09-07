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
async def create_challenge(sn: str):

    device = db.devices.find_one({"sn": sn})
    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    challenge = secrets.token_hex(16)
    expires_at = time.time() + CHALLENGE_EXPIRATION_TIME

    db.challenges.insert_one({
        "sn": sn,
        "challenge": challenge,
        "expires_at": expires_at
    })

    return {
        "sn": sn,
        "challenge": challenge,
        "expires_at": expires_at
    }

class ChallegeIn(BaseModel):
    sn: str
    challenge: str
    expires_at: int
    signature: str


@router.post("/auth/token")
async def verify_device_auth(body: ChallegeIn):
    challenge = body.json()

    # Validate the challenge
    if not (challenge["expires_at"] > time.time()):
        raise HTTPException(status_code=403, detail="Expired challenge")

    challenge_entry = db.challenges.find_one({
        "sn": challenge["sn"],
        "challenge": challenge["challenge"]
    })

    if not challenge_entry:
        raise HTTPException(status_code=403, detail="Invalid challenge")

    # Get the device public key
    device = db.devices.find_one({"sn": challenge["sn"]}, {"public_key": 1})
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

    filter = {"sn": challenge["sn"]}
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
        "sn": challenge["sn"],
        "access_token": token,
        "expires_at": expires_at
    }