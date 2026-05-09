#!/usr/bin/env python3
"""
create_super_admin.py

Run this once to bootstrap the first platform super admin account.

Usage:
    cd fastAPi-Carte
    python create_super_admin.py

Environment variables:
    MONGODB_URL  — MongoDB connection string (reads from .env if not set)
"""

import asyncio
import os
import sys
from pathlib import Path

# Load .env
env_path = Path(__file__).parent / ".env"
if env_path.exists():
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                os.environ.setdefault(key.strip(), value.strip())

import bcrypt
from motor.motor_asyncio import AsyncIOMotorClient
from datetime import datetime

MONGO_URL = os.getenv("MONGODB_URL", "mongodb://localhost:27017")
DB_NAME = os.getenv("DB_NAME", "carte_pos")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


async def create_super_admin():
    print("\n=== Carte POS — Create Platform Super Admin ===\n")

    # Get credentials
    name = input("Admin name [Platform Admin]: ").strip() or "Platform Admin"
    email = input("Admin email: ").strip().lower()
    if not email:
        print("❌  Email is required.")
        sys.exit(1)

    import getpass
    password = getpass.getpass("Password: ")
    if len(password) < 8:
        print("❌  Password must be at least 8 characters.")
        sys.exit(1)

    confirm = getpass.getpass("Confirm password: ")
    if password != confirm:
        print("❌  Passwords do not match.")
        sys.exit(1)

    # Connect to DB
    print(f"\nConnecting to MongoDB ({MONGO_URL[:30]}...)...")
    client = AsyncIOMotorClient(MONGO_URL)
    db = client[DB_NAME]
    collection = db["platform_admins"]

    # Check for duplicate
    existing = await collection.find_one({"email": email})
    if existing:
        print(f"⚠️   A platform admin with email '{email}' already exists.")
        overwrite = input("Overwrite? (y/N): ").strip().lower()
        if overwrite != "y":
            print("Aborted.")
            client.close()
            sys.exit(0)
        await collection.delete_one({"email": email})

    # Insert
    doc = {
        "name": name,
        "email": email,
        "password_hash": hash_password(password),
        "is_active": True,
        "last_login": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
    }
    result = await collection.insert_one(doc)

    print(f"\n✅  Platform super admin created!")
    print(f"   ID:    {result.inserted_id}")
    print(f"   Name:  {name}")
    print(f"   Email: {email}")
    print(f"\nLogin at: http://localhost:3000/admin/login\n")

    client.close()


if __name__ == "__main__":
    asyncio.run(create_super_admin())
