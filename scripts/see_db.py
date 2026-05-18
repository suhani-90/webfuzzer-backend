"""
scripts/seed_db.py
───────────────────
Seeds the database with a default admin user and sample target
for development and demonstration purposes.

Run with:  python -m scripts.seed_db
"""

import asyncio
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core.security import hash_password
from app.db.init_db import create_tables
from app.db.session import AsyncSessionLocal
from app.models.user import User
from app.models.target import Target


async def seed():
    print("🌱 Seeding SmartFuzz database...")

    await create_tables()

    async with AsyncSessionLocal() as db:
        from sqlalchemy.future import select

        # Create admin user if not exists
        result = await db.execute(
            select(User).where(User.email == "admin@smartfuzz.io")
        )
        if not result.scalar_one_or_none():
            admin = User(
                email="admin@smartfuzz.io",
                username="admin",
                hashed_password=hash_password("Admin@SmartFuzz1"),
                full_name="SmartFuzz Admin",
                is_superuser=True,
                is_active=True,
            )
            db.add(admin)
            await db.flush()

            # Create demo target
            target = Target(
                user_id=admin.id,
                url="http://testphp.vulnweb.com",
                name="VulnWeb Demo (Public Test Site)",
                description="Acunetix public demo vulnerable PHP app — safe for testing.",
                scan_depth=2,
                rate_limit_rps=3.0,
            )
            db.add(target)
            await db.commit()

            print("✅ Admin user created:")
            print("   Email:    admin@smartfuzz.io")
            print("   Password: Admin@SmartFuzz1")
            print("   Target:   http://testphp.vulnweb.com")
        else:
            print("ℹ️  Admin user already exists — skipping seed.")

    print("✅ Database seeded successfully.")


if __name__ == "__main__":
    asyncio.run(seed())
