# app/routes/platform.py
"""
Platform-level routes for the Carte SaaS super admin.
These routes authenticate against `platform_admins` collection —
completely separate from tenant employees.

Key features:
  - Auto-seeds a default admin (admin@ourcarte.com / 12341234) on first boot
  - Enforces password change on first login (password_changed flag)
  - Allows adding more super admins (with temp password + forced change)
  - Full tenant CRUD and cross-tenant analytics
"""

from fastapi import APIRouter, HTTPException, Depends, Body, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.database import get_collection
from app.models.platform import PlatformAdmin
from app.utils.response_helpers import success_response, error_response, handle_generic_exception
from bson import ObjectId
import bcrypt
import jwt
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

router = APIRouter(prefix="/api/platform", tags=["platform"])

# --- Config ---
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here-change-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "1440"))  # 24h

platform_oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/platform/login")


# ─── Utilities ────────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    if not hashed or not hashed.startswith("$2b$"):
        return plain == hashed
    return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))


def create_platform_token(admin_id: str, email: str, password_changed: bool = False) -> str:
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    payload = {
        "sub": email,
        "platform_admin_id": admin_id,
        "is_super_admin": True,
        "password_changed": password_changed,   # Carried in JWT for fast checks
        "exp": expire,
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_platform_admin(
    token: str = Depends(platform_oauth2_scheme),
) -> Dict[str, Any]:
    """JWT dependency — verifies is_super_admin flag.
    Does NOT enforce password_changed here; each endpoint that needs
    a fully-activated admin should call require_password_changed()."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate platform admin credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if not payload.get("is_super_admin"):
            raise credentials_exception
        if not payload.get("platform_admin_id"):
            raise credentials_exception
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Platform admin token has expired")
    except jwt.PyJWTError:
        raise credentials_exception


async def require_password_changed(
    current_admin: Dict = Depends(get_current_platform_admin),
) -> Dict[str, Any]:
    """Additional guard: blocks access if admin hasn't changed their password yet."""
    if not current_admin.get("password_changed", False):
        raise HTTPException(
            status_code=403,
            detail="You must change your password before accessing the platform. "
                   "Please use the /api/platform/change-password endpoint.",
        )
    return current_admin


# ─── Startup Bootstrap ────────────────────────────────────────────────────────

async def seed_default_platform_admin() -> None:
    """
    Called at application startup.
    If the platform_admins collection is empty, creates the default super admin:
        email:    admin@ourcarte.com
        password: 12341234   (temporary — must be changed on first login)
    """
    try:
        collection = get_collection("platform_admins")
        count = await collection.count_documents({})
        if count > 0:
            print("✅ [Platform] Default admin already exists — skipping seed.")
            return

        default_email = "admin@ourcarte.com"
        default_password = "12341234"

        doc = {
            "name": "Platform Admin",
            "email": default_email,
            "password_hash": hash_password(default_password),
            "is_active": True,
            "password_changed": False,   # Forces password reset on first login
            "last_login": None,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        result = await collection.insert_one(doc)
        print(
            f"✅ [Platform] Default super admin created!\n"
            f"   Email:    {default_email}\n"
            f"   Password: {default_password} (TEMPORARY — change immediately)\n"
            f"   ID:       {result.inserted_id}"
        )
    except Exception as e:
        print(f"❌ [Platform] Failed to seed default admin: {e}")


# ─── Auth ─────────────────────────────────────────────────────────────────────

@router.post("/login")
async def platform_login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Authenticate a platform admin. Returns token + password_changed status."""
    try:
        admins_collection = get_collection("platform_admins")
        admin = await admins_collection.find_one({
            "$or": [
                {"email": form_data.username},
                {"email": form_data.username.lower()},
            ]
        })

        if not admin:
            return error_response(message="Invalid credentials", code=401)

        if not verify_password(form_data.password, admin.get("password_hash", "")):
            return error_response(message="Invalid credentials", code=401)

        if not admin.get("is_active", True):
            return error_response(message="This admin account has been deactivated", code=403)

        admin_id = str(admin["_id"])
        password_changed = admin.get("password_changed", False)
        access_token = create_platform_token(admin_id, admin["email"], password_changed)

        await admins_collection.update_one(
            {"_id": admin["_id"]},
            {"$set": {"last_login": datetime.utcnow()}}
        )

        return success_response(data={
            "access_token": access_token,
            "token_type": "bearer",
            "password_changed": password_changed,   # Frontend uses this to redirect
            "admin": {
                "id": admin_id,
                "name": admin.get("name"),
                "email": admin.get("email"),
                "is_super_admin": True,
                "password_changed": password_changed,
            }
        })
    except Exception as e:
        return handle_generic_exception(e)


@router.post("/change-password")
async def change_platform_admin_password(
    current_password: str = Body(...),
    new_password: str = Body(...),
    current_admin: Dict = Depends(get_current_platform_admin),
):
    """
    Change the current platform admin's password.
    On first login (password_changed=False) this is the ONLY accessible endpoint.
    After a successful change, password_changed is set to True.
    """
    try:
        if len(new_password) < 8:
            return error_response(message="New password must be at least 8 characters", code=400)

        admins_collection = get_collection("platform_admins")
        admin = await admins_collection.find_one(
            {"_id": ObjectId(current_admin["platform_admin_id"])}
        )
        if not admin:
            return error_response(message="Admin not found", code=404)

        if not verify_password(current_password, admin.get("password_hash", "")):
            return error_response(message="Current password is incorrect", code=400)

        if current_password == new_password:
            return error_response(message="New password must be different from the current password", code=400)

        new_hash = hash_password(new_password)
        await admins_collection.update_one(
            {"_id": admin["_id"]},
            {"$set": {
                "password_hash": new_hash,
                "password_changed": True,
                "updated_at": datetime.utcnow(),
            }}
        )

        # Issue a fresh token with updated password_changed=True
        admin_id = str(admin["_id"])
        new_token = create_platform_token(admin_id, admin["email"], password_changed=True)

        return success_response(data={
            "message": "Password changed successfully",
            "access_token": new_token,
            "token_type": "bearer",
            "admin": {
                "id": admin_id,
                "name": admin.get("name"),
                "email": admin.get("email"),
                "is_super_admin": True,
                "password_changed": True,
            }
        })
    except Exception as e:
        return handle_generic_exception(e)


@router.get("/me")
async def get_platform_me(current_admin: Dict = Depends(get_current_platform_admin)):
    """Get current platform admin profile. Accessible even before password change."""
    try:
        admins_collection = get_collection("platform_admins")
        admin = await admins_collection.find_one(
            {"_id": ObjectId(current_admin["platform_admin_id"])}
        )
        if not admin:
            return error_response(message="Admin not found", code=404)

        instance = PlatformAdmin.from_mongo(admin)
        return success_response(data=instance.to_response_dict())
    except Exception as e:
        return handle_generic_exception(e)


# ─── Platform Admin Management ────────────────────────────────────────────────

@router.get("/admins")
async def list_platform_admins(current_admin: Dict = Depends(require_password_changed)):
    """List all platform admins."""
    try:
        admins_collection = get_collection("platform_admins")
        admins = []
        async for doc in admins_collection.find({}):
            instance = PlatformAdmin.from_mongo(doc)
            admins.append(instance.to_response_dict())
        return success_response(data=admins)
    except Exception as e:
        return handle_generic_exception(e)


@router.post("/admins")
async def create_platform_admin(
    name: str = Body(...),
    email: str = Body(...),
    current_admin: Dict = Depends(require_password_changed),
):
    """
    Create a new platform admin with a temporary password.
    The new admin MUST change their password on first login.
    The temporary password is returned in the response so the caller
    can communicate it securely (e.g., via email).
    """
    try:
        admins_collection = get_collection("platform_admins")
        existing = await admins_collection.find_one({"email": email.lower()})
        if existing:
            return error_response(message="An admin with this email already exists", code=409)

        # Generate a safe temp password
        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        temp_password = "".join(secrets.choice(alphabet) for _ in range(12))

        new_admin = {
            "name": name,
            "email": email.lower(),
            "password_hash": hash_password(temp_password),
            "is_active": True,
            "password_changed": False,   # Must change on first login
            "last_login": None,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        result = await admins_collection.insert_one(new_admin)
        created = await admins_collection.find_one({"_id": result.inserted_id})
        instance = PlatformAdmin.from_mongo(created)

        response_data = instance.to_response_dict()
        response_data["temp_password"] = temp_password   # Return so caller can share it

        return success_response(data=response_data, code=201)
    except Exception as e:
        return handle_generic_exception(e)


@router.put("/admins/{admin_id}")
async def update_platform_admin(
    admin_id: str,
    name: Optional[str] = Body(None),
    is_active: Optional[bool] = Body(None),
    current_admin: Dict = Depends(require_password_changed),
):
    """Update a platform admin's name or active status."""
    try:
        if admin_id == current_admin["platform_admin_id"] and is_active is False:
            return error_response(message="You cannot deactivate your own account", code=400)

        admins_collection = get_collection("platform_admins")
        updates: Dict[str, Any] = {"updated_at": datetime.utcnow()}
        if name is not None:
            updates["name"] = name
        if is_active is not None:
            updates["is_active"] = is_active

        result = await admins_collection.update_one(
            {"_id": ObjectId(admin_id)},
            {"$set": updates}
        )
        if result.matched_count == 0:
            return error_response(message="Admin not found", code=404)

        updated = await admins_collection.find_one({"_id": ObjectId(admin_id)})
        return success_response(data=PlatformAdmin.from_mongo(updated).to_response_dict())
    except Exception as e:
        return handle_generic_exception(e)


@router.put("/admins/{admin_id}/reset-password")
async def reset_admin_password(
    admin_id: str,
    current_admin: Dict = Depends(require_password_changed),
):
    """
    Reset another admin's password to a new temporary one.
    Sets password_changed=False so they are forced to change it on next login.
    Returns the new temp password.
    """
    try:
        if admin_id == current_admin["platform_admin_id"]:
            return error_response(message="Use /change-password to update your own password", code=400)

        import secrets
        import string
        alphabet = string.ascii_letters + string.digits
        temp_password = "".join(secrets.choice(alphabet) for _ in range(12))

        admins_collection = get_collection("platform_admins")
        result = await admins_collection.update_one(
            {"_id": ObjectId(admin_id)},
            {"$set": {
                "password_hash": hash_password(temp_password),
                "password_changed": False,
                "updated_at": datetime.utcnow(),
            }}
        )
        if result.matched_count == 0:
            return error_response(message="Admin not found", code=404)

        return success_response(data={
            "message": "Password reset successfully",
            "temp_password": temp_password,
        })
    except Exception as e:
        return handle_generic_exception(e)


@router.delete("/admins/{admin_id}")
async def delete_platform_admin(
    admin_id: str,
    current_admin: Dict = Depends(require_password_changed),
):
    """Permanently delete a platform admin. Cannot delete yourself."""
    try:
        if admin_id == current_admin["platform_admin_id"]:
            return error_response(message="You cannot delete your own account", code=400)

        admins_collection = get_collection("platform_admins")

        # Prevent deleting the last admin
        count = await admins_collection.count_documents({"is_active": True})
        if count <= 1:
            return error_response(message="Cannot delete the last active platform admin", code=400)

        result = await admins_collection.delete_one({"_id": ObjectId(admin_id)})
        if result.deleted_count == 0:
            return error_response(message="Admin not found", code=404)

        return success_response(data={"deleted": True})
    except Exception as e:
        return handle_generic_exception(e)


# ─── Tenant Management ────────────────────────────────────────────────────────

@router.get("/tenants")
async def list_all_tenants(current_admin: Dict = Depends(require_password_changed)):
    """List all tenants with aggregated stats."""
    try:
        tenants_col = get_collection("tenants")
        stores_col = get_collection("stores")
        employees_col = get_collection("employees")
        orders_col = get_collection("orders")

        tenants = []
        async for tenant in tenants_col.find({}):
            tenant_id = str(tenant["_id"])
            store_count = await stores_col.count_documents({"tenant_id": tenant_id})
            employee_count = await employees_col.count_documents({"tenant_id": tenant_id})

            pipeline = [
                {"$match": {"tenant_id": tenant_id, "payment_status": "paid"}},
                {"$group": {"_id": None, "total": {"$sum": "$total_amount"}, "count": {"$sum": 1}}}
            ]
            rev_result = await orders_col.aggregate(pipeline).to_list(1)
            revenue = rev_result[0]["total"] if rev_result else 0
            order_count = rev_result[0]["count"] if rev_result else 0

            tenants.append({
                "id": tenant_id,
                "name": tenant.get("name"),
                "email": tenant.get("email"),
                "phone": tenant.get("phone"),
                "address": tenant.get("address"),
                "created_at": tenant.get("created_at"),
                "store_count": store_count,
                "employee_count": employee_count,
                "order_count": order_count,
                "revenue": revenue,
                "status": tenant.get("status", "active"),
                "plan": tenant.get("plan", "Standard"),
            })

        return success_response(data=tenants)
    except Exception as e:
        return handle_generic_exception(e)


@router.get("/tenants/{tenant_id}")
async def get_tenant_detail(
    tenant_id: str,
    current_admin: Dict = Depends(require_password_changed),
):
    """Get a single tenant with full detail: stores, employees, recent orders."""
    try:
        tenants_col = get_collection("tenants")
        stores_col = get_collection("stores")
        employees_col = get_collection("employees")
        orders_col = get_collection("orders")
        access_roles_col = get_collection("access_roles")

        tenant = await tenants_col.find_one({"_id": ObjectId(tenant_id)})
        if not tenant:
            return error_response(message="Tenant not found", code=404)

        stores = []
        async for store in stores_col.find({"tenant_id": tenant_id}):
            stores.append({
                "id": str(store["_id"]),
                "name": store.get("name"),
                "address": store.get("address"),
                "phone": store.get("phone"),
                "email": store.get("email"),
            })

        employees = []
        async for emp in employees_col.find({"tenant_id": tenant_id}):
            role_name = "Unknown"
            if emp.get("main_access_role_id"):
                try:
                    role = await access_roles_col.find_one({"_id": ObjectId(emp["main_access_role_id"])})
                    if role:
                        role_name = role.get("name", "Unknown")
                except Exception:
                    pass
            employees.append({
                "id": str(emp["_id"]),
                "first_name": emp.get("first_name"),
                "last_name": emp.get("last_name"),
                "role": role_name,
                "store_id": emp.get("store_id"),
                "hire_date": str(emp.get("hire_date", "")),
            })

        orders = []
        async for order in orders_col.find(
            {"tenant_id": tenant_id},
            sort=[("created_at", -1)],
            limit=20
        ):
            orders.append({
                "id": str(order["_id"]),
                "total_amount": order.get("total_amount", 0),
                "status": order.get("status"),
                "payment_status": order.get("payment_status"),
                "order_type": order.get("order_type"),
                "created_at": str(order.get("created_at", "")),
            })

        pipeline = [
            {"$match": {"tenant_id": tenant_id, "payment_status": "paid"}},
            {"$group": {"_id": None, "total": {"$sum": "$total_amount"}, "count": {"$sum": 1}}}
        ]
        rev_result = await orders_col.aggregate(pipeline).to_list(1)
        revenue = rev_result[0]["total"] if rev_result else 0
        order_count = rev_result[0]["count"] if rev_result else 0

        return success_response(data={
            "id": tenant_id,
            "name": tenant.get("name"),
            "email": tenant.get("email"),
            "phone": tenant.get("phone"),
            "address": tenant.get("address"),
            "created_at": str(tenant.get("created_at", "")),
            "status": tenant.get("status", "active"),
            "plan": tenant.get("plan", "Standard"),
            "revenue": revenue,
            "order_count": order_count,
            "stores": stores,
            "employees": employees,
            "recent_orders": orders,
        })
    except Exception as e:
        return handle_generic_exception(e)


@router.post("/tenants")
async def create_tenant(
    name: str = Body(...),
    email: str = Body(...),
    phone: Optional[str] = Body(None),
    address: Optional[str] = Body(None),
    plan: str = Body("Standard"),
    current_admin: Dict = Depends(require_password_changed),
):
    """Create a new tenant (restaurant)."""
    try:
        tenants_col = get_collection("tenants")
        existing = await tenants_col.find_one({"email": email.lower()})
        if existing:
            return error_response(message="A tenant with this email already exists", code=409)

        now = datetime.utcnow()
        new_tenant = {
            "name": name,
            "email": email.lower(),
            "phone": phone or "",
            "address": address or "",
            "plan": plan,
            "status": "active",
            "password": "",
            "customer_page_settings": {},
            "created_at": now,
            "updated_at": now,
        }
        result = await tenants_col.insert_one(new_tenant)
        created = await tenants_col.find_one({"_id": result.inserted_id})

        return success_response(data={
            "id": str(created["_id"]),
            "name": created["name"],
            "email": created["email"],
            "plan": created["plan"],
            "status": created["status"],
            "created_at": str(created["created_at"]),
        }, code=201)
    except Exception as e:
        return handle_generic_exception(e)


@router.put("/tenants/{tenant_id}")
async def update_tenant(
    tenant_id: str,
    name: Optional[str] = Body(None),
    email: Optional[str] = Body(None),
    phone: Optional[str] = Body(None),
    address: Optional[str] = Body(None),
    plan: Optional[str] = Body(None),
    status: Optional[str] = Body(None),
    current_admin: Dict = Depends(require_password_changed),
):
    """Update tenant details or status."""
    try:
        tenants_col = get_collection("tenants")
        updates: Dict[str, Any] = {"updated_at": datetime.utcnow()}
        if name is not None:
            updates["name"] = name
        if email is not None:
            updates["email"] = email.lower()
        if phone is not None:
            updates["phone"] = phone
        if address is not None:
            updates["address"] = address
        if plan is not None:
            updates["plan"] = plan
        if status is not None:
            updates["status"] = status

        result = await tenants_col.update_one(
            {"_id": ObjectId(tenant_id)},
            {"$set": updates}
        )
        if result.matched_count == 0:
            return error_response(message="Tenant not found", code=404)

        updated = await tenants_col.find_one({"_id": ObjectId(tenant_id)})
        return success_response(data={
            "id": str(updated["_id"]),
            "name": updated.get("name"),
            "email": updated.get("email"),
            "plan": updated.get("plan"),
            "status": updated.get("status"),
        })
    except Exception as e:
        return handle_generic_exception(e)


@router.delete("/tenants/{tenant_id}")
async def delete_tenant(
    tenant_id: str,
    current_admin: Dict = Depends(require_password_changed),
):
    """Soft-delete (suspend) a tenant."""
    try:
        tenants_col = get_collection("tenants")
        result = await tenants_col.update_one(
            {"_id": ObjectId(tenant_id)},
            {"$set": {"status": "suspended", "updated_at": datetime.utcnow()}}
        )
        if result.matched_count == 0:
            return error_response(message="Tenant not found", code=404)
        return success_response(data={"suspended": True})
    except Exception as e:
        return handle_generic_exception(e)


# ─── Platform Analytics ───────────────────────────────────────────────────────

@router.get("/analytics")
async def get_platform_analytics(
    days: int = 30,
    current_admin: Dict = Depends(require_password_changed),
):
    """Cross-tenant analytics: revenue trend, top tenants, order volumes."""
    try:
        orders_col = get_collection("orders")
        tenants_col = get_collection("tenants")
        from_date = datetime.utcnow() - timedelta(days=days)

        total_pipeline = [
            {"$match": {"payment_status": "paid"}},
            {"$group": {"_id": None, "total": {"$sum": "$total_amount"}, "count": {"$sum": 1}}}
        ]
        total_result = await orders_col.aggregate(total_pipeline).to_list(1)
        total_revenue = total_result[0]["total"] if total_result else 0
        total_orders = total_result[0]["count"] if total_result else 0

        daily_pipeline = [
            {"$match": {"payment_status": "paid", "created_at": {"$gte": from_date}}},
            {
                "$group": {
                    "_id": {
                        "$dateToString": {
                            "format": "%Y-%m-%d",
                            "date": {"$toDate": "$created_at"}
                        }
                    },
                    "revenue": {"$sum": "$total_amount"},
                    "orders": {"$sum": 1}
                }
            },
            {"$sort": {"_id": 1}}
        ]
        daily_data = await orders_col.aggregate(daily_pipeline).to_list(days + 1)

        tenant_pipeline = [
            {"$match": {"payment_status": "paid"}},
            {"$group": {"_id": "$tenant_id", "revenue": {"$sum": "$total_amount"}, "orders": {"$sum": 1}}},
            {"$sort": {"revenue": -1}},
            {"$limit": 5}
        ]
        top_tenants_raw = await orders_col.aggregate(tenant_pipeline).to_list(5)

        top_tenants = []
        for t in top_tenants_raw:
            tenant_id = t["_id"]
            name = "Unattributed"
            if tenant_id:
                try:
                    doc = await tenants_col.find_one({"_id": ObjectId(tenant_id)})
                    name = doc.get("name", "Unknown") if doc else "Unknown"
                except Exception:
                    pass
            top_tenants.append({
                "tenant_id": tenant_id,
                "tenant_name": name,
                "revenue": t["revenue"],
                "orders": t["orders"],
            })

        tenant_count = await tenants_col.count_documents({})
        active_tenant_count = await tenants_col.count_documents({"status": "active"})

        return success_response(data={
            "summary": {
                "total_revenue": total_revenue,
                "total_orders": total_orders,
                "total_tenants": tenant_count,
                "active_tenants": active_tenant_count,
            },
            "daily_revenue": [
                {"date": d["_id"], "revenue": d["revenue"], "orders": d["orders"]}
                for d in daily_data
            ],
            "top_tenants": top_tenants,
        })
    except Exception as e:
        return handle_generic_exception(e)
