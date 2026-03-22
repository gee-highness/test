from fastapi import APIRouter, HTTPException, Depends, status, Body
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from app.database import get_collection
from app.models.hr import Employee
from app.models.response import StandardResponse, EmployeeResponse, LoginResponse
from app.utils.response_helpers import success_response, error_response, handle_generic_exception
from bson import ObjectId
import bcrypt
import jwt
import os
import secrets
import string
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional

router = APIRouter(prefix="/api", tags=["auth"])
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/login")

# --- Configuration & Environment Variables ---
SECRET_KEY = os.getenv("JWT_SECRET_KEY", "your-secret-key-here-change-in-production")
ALGORITHM = os.getenv("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "30"))

# --- Utility Functions ---

def hash_password(password: str) -> str:
    """Hash a password for storing."""
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a stored password against one provided by user."""
    if not hashed_password:
        return False
    if not hashed_password.startswith("$2b$"):
        return plain_password == hashed_password
    return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))

def create_access_token(data: dict, expires_delta: timedelta = None):
    """Creates a signed JWT access token."""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    
    to_encode.update({"exp": expire, "iat": datetime.utcnow()})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def generate_random_password(length: int = 12) -> str:
    """Generate a secure random password."""
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
    return ''.join(secrets.choice(alphabet) for _ in range(length))

async def _fetch_and_enrich_employee_data(employee_id: str) -> Dict[str, Any]:
    """
    Fetches employee data and enriches it with detailed role information.
    """
    try:
        employees_collection = get_collection("employees")
        access_roles_collection = get_collection("access_roles")
        
        employee = await employees_collection.find_one({"_id": ObjectId(employee_id)})
        if not employee:
            raise HTTPException(status_code=404, detail="Employee data not found")
            
        # Convert MongoDB document to Employee Pydantic model for base data
        employee_data = Employee.from_mongo(employee)
        employee_dict = employee_data.model_dump()
        
        # 1. Get main access role details
        main_access_role = None
        if employee.get("main_access_role_id"):
            main_access_role = await access_roles_collection.find_one(
                {"_id": ObjectId(employee["main_access_role_id"])}
            )
        
        if main_access_role:
            employee_dict["main_access_role"] = {
                "id": str(main_access_role["_id"]),
                "name": main_access_role.get("name", ""),
                "description": main_access_role.get("description", ""),
                "permissions": main_access_role.get("permissions", []),
                "landing_page": main_access_role.get("landing_page", "")
            }
        
        # 2. Get all access roles for the employee
        employee_access_roles: List[Dict] = []
        role_ids = [ObjectId(rid) for rid in employee.get("access_role_ids", [])]
        if role_ids:
            roles = await access_roles_collection.find({"_id": {"$in": role_ids}})
            for role in roles:
                employee_access_roles.append({
                    "id": str(role["_id"]),
                    "name": role.get("name", ""),
                    "description": role.get("description", ""),
                    "permissions": role.get("permissions", []),
                    "landing_page": role.get("landing_page", "")
                })
        
        employee_dict["access_roles"] = employee_access_roles
        
        return employee_dict
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/debug/users", response_model=StandardResponse[List[dict]])
async def debug_users():
    """Debug endpoint to see all users and their emails"""
    try:
        users_collection = get_collection("users")
        users = []
        user_docs = await users_collection.find()
        for user in user_docs:
            users.append({
                "id": str(user["_id"]),
                "username": user.get("username"),
                "email": user.get("email"),
                "has_password": bool(user.get("password")),
                "password_length": len(user.get("password", "")),
                "password_changed": user.get("password_changed", True),
                "password_prefix": user.get("password", "")[:10] + "..." if user.get("password") else None
            })
        return success_response(data=users)
    except Exception as e:
        return handle_generic_exception(e)

# --- JWT Functions ---

async def get_current_employee(token: str = Depends(oauth2_scheme)):
    """Verifies the JWT token and returns the employee data."""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        employee_id: str = payload.get("employee_id")
        if employee_id is None:
            raise credentials_exception
            
        employees_collection = get_collection("employees")
        employee_doc = await employees_collection.find_one({"_id": ObjectId(employee_id)})

        if employee_doc is None:
            raise credentials_exception

        return {"id": employee_id, "store_id": payload.get("store_id")}

    except jwt.PyJWTError:
        raise credentials_exception

# --- Public Endpoints ---

@router.post("/register", response_model=StandardResponse[EmployeeResponse])
async def register_employee(employee: Employee):
    """Registers a new employee."""
    try:
        employees_collection = get_collection("employees")
        
        # Check for duplicate email
        if await employees_collection.find_one({"email": employee.email}):
            return error_response(
                message=f"Employee with email '{employee.email}' already exists.",
                code=409
            )

        # Insert the new employee using the helper function
        from app.utils.mongo_helpers import to_mongo_dict
        employee_dict = to_mongo_dict(employee)
        employee_dict["password"] = hash_password("defaultpassword")
        
        new_employee = await employees_collection.insert_one(employee_dict)
        created_employee = await employees_collection.find_one({"_id": new_employee.inserted_id})
        
        return success_response(
            data=Employee.from_mongo(created_employee),
            message="Employee registered successfully",
            code=201
        )
    except Exception as e:
        return handle_generic_exception(e)

@router.post("/login", response_model=StandardResponse[LoginResponse])
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """Handles employee login, validates credentials, and generates a JWT."""
    try:
        users_collection = get_collection("users")
        
        # Find user by email or username
        user = await users_collection.find_one({
            "$or": [
                {"email": form_data.username},
                {"username": form_data.username}
            ]
        })
        
        if not user:
            return error_response(message="Invalid credentials", code=401)
        
        # Check password
        password_valid = verify_password(form_data.password, user.get("password", ""))
        
        if not password_valid:
            return error_response(message="Invalid credentials", code=401)
        
        # Check if password needs to be changed
        # CRITICAL: If password_changed is False or doesn't exist, user needs to change password
        password_changed = user.get("password_changed", False)  # Default to False for new users
        
        # Find employee linked to this user
        employees_collection = get_collection("employees")
        employee = await employees_collection.find_one({"user_id": str(user["_id"])})
        
        if not employee:
            return error_response(message="Account not authorized for employee access", code=403)
        
        employee_id = str(employee["_id"])
        
        # Get enriched employee data
        enriched_employee_data = await _fetch_and_enrich_employee_data(employee_id)
        
        # Create access token
        access_token = create_access_token(data={
            "sub": user["email"], 
            "user_id": str(user["_id"]),
            "employee_id": employee_id,
            "store_id": enriched_employee_data.get("store_id", ""),
            "roles": enriched_employee_data.get("access_role_ids", []),
            "password_changed": password_changed  # Add to token
        })
        
        return success_response(data={
            "access_token": access_token,
            "token_type": "bearer",
            "employee": enriched_employee_data,
            "password_changed": password_changed  # Return to frontend
        })
    except HTTPException as e:
        return error_response(message=str(e.detail), code=e.status_code)
    except Exception as e:
        return handle_generic_exception(e)

@router.post("/change-password", response_model=StandardResponse[dict])
async def change_password(
    user_id: str = Body(...),
    current_password: Optional[str] = Body(None),
    new_password: str = Body(...),
    confirm_password: str = Body(...)
):
    """
    Change user password.
    For first-time login, current_password is not required.
    For subsequent changes, current_password is required.
    """
    try:
        users_collection = get_collection("users")
        
        # Find user
        user = await users_collection.find_one({"_id": ObjectId(user_id)})
        
        if not user:
            return error_response(message="User not found", code=404)
        
        # Validate new password
        if len(new_password) < 8:
            return error_response(
                message="Password must be at least 8 characters long",
                code=400
            )
        
        if new_password != confirm_password:
            return error_response(message="Passwords do not match", code=400)
        
        # Check if this is a password change after first login
        is_first_login = user.get("password_changed", True) == False
        
        # If not first login, verify current password
        if not is_first_login:
            if not current_password:
                return error_response(
                    message="Current password is required",
                    code=400
                )
            
            password_valid = verify_password(current_password, user.get("password", ""))
            if not password_valid:
                return error_response(
                    message="Current password is incorrect",
                    code=401
                )
        
        # Hash and update password - CRITICAL: Set password_changed to True
        hashed_password = hash_password(new_password)
        
        result = await users_collection.update_one(
            {"_id": ObjectId(user_id)},
            {
                "$set": {
                    "password": hashed_password,
                    "password_changed": True,  # <-- THIS IS THE KEY FIX
                    "password_updated_at": datetime.utcnow().isoformat()
                }
            }
        )
        
        if result.modified_count == 0:
            return error_response(message="Failed to update password", code=500)
        
        return success_response(
            data={
                "message": "Password changed successfully",
                "password_changed": True
            },
            message="Password changed successfully"
        )
        
    except Exception as e:
        return handle_generic_exception(e)

@router.post("/reset-password-request", response_model=StandardResponse[dict])
async def reset_password_request(email: str = Body(...)):
    """
    Request password reset. Sends reset link via email (placeholder).
    """
    try:
        users_collection = get_collection("users")
        
        user = await users_collection.find_one({"email": email})
        
        if not user:
            # Don't reveal that user doesn't exist for security
            return success_response(
                data=None,
                message="If an account exists with that email, a password reset link has been sent."
            )
        
        # Generate reset token (you can store this in database)
        reset_token = generate_random_password(32)
        
        # Store reset token with expiration (15 minutes)
        await users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "reset_token": reset_token,
                    "reset_token_expires": (datetime.utcnow() + timedelta(minutes=15)).isoformat()
                }
            }
        )
        
        # Here you would send an email with the reset link
        # reset_link = f"{FRONTEND_URL}/reset-password?token={reset_token}"
        
        return success_response(
            data={
                "reset_token": reset_token,  # Only for development, remove in production
                "message": "Password reset email sent"
            },
            message="If an account exists with that email, a password reset link has been sent."
        )
        
    except Exception as e:
        return handle_generic_exception(e)

@router.post("/reset-password", response_model=StandardResponse[dict])
async def reset_password(
    token: str = Body(...),
    new_password: str = Body(...),
    confirm_password: str = Body(...)
):
    """
    Reset password using reset token.
    """
    try:
        users_collection = get_collection("users")
        
        # Validate passwords
        if len(new_password) < 8:
            return error_response(
                message="Password must be at least 8 characters long",
                code=400
            )
        
        if new_password != confirm_password:
            return error_response(message="Passwords do not match", code=400)
        
        # Find user by reset token
        user = await users_collection.find_one({
            "reset_token": token,
            "reset_token_expires": {"$gt": datetime.utcnow().isoformat()}
        })
        
        if not user:
            return error_response(
                message="Invalid or expired reset token",
                code=400
            )
        
        # Hash and update password
        hashed_password = hash_password(new_password)
        
        await users_collection.update_one(
            {"_id": user["_id"]},
            {
                "$set": {
                    "password": hashed_password,
                    "password_changed": True,
                    "password_updated_at": datetime.utcnow().isoformat()
                },
                "$unset": {
                    "reset_token": "",
                    "reset_token_expires": ""
                }
            }
        )
        
        return success_response(
            data=None,
            message="Password has been reset successfully. You can now log in with your new password."
        )
        
    except Exception as e:
        return handle_generic_exception(e)

async def get_current_employee_full(token: str = Depends(oauth2_scheme)) -> Dict[str, Any]:
    """
    Decodes the JWT token and fetches the current employee's detailed information.
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        employee_id: str = payload.get("employee_id")
        if employee_id is None:
            raise credentials_exception
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token has expired", headers={"WWW-Authenticate": "Bearer"})
    except jwt.JWTError:
        raise credentials_exception
    
    # Fetch and enrich employee data
    try:
        enriched_employee_data = await _fetch_and_enrich_employee_data(employee_id)
    except HTTPException:
        raise credentials_exception
    
    return enriched_employee_data

@router.get("/employees/me", response_model=StandardResponse[EmployeeResponse])
async def read_employees_me(current_employee: Dict[str, Any] = Depends(get_current_employee_full)):
    """Retrieves the full profile of the currently authenticated employee."""
    return success_response(data=current_employee)

@router.post("/logout", response_model=StandardResponse[dict])
async def logout():
    """Provides a successful logout message."""
    return success_response(data=None, message="Successfully logged out")

@router.post("/refresh-token", response_model=StandardResponse[LoginResponse])
async def refresh_token(current_employee: Dict[str, Any] = Depends(get_current_employee_full)):
    """Generates a new JWT for an authenticated user."""
    try:
        users_collection = get_collection("users")
        user = await users_collection.find_one({"_id": ObjectId(current_employee.get("user_id"))})
        
        if not user:
            return error_response(message="User not found", code=404)
        
        # Get password_changed status
        password_changed = user.get("password_changed", True)
        
        access_token = create_access_token(data={
            "sub": user["email"], 
            "user_id": str(user["_id"]),
            "employee_id": current_employee.get("id"),
            "store_id": current_employee.get("store_id", ""),
            "roles": current_employee.get("access_role_ids", []),
            "password_changed": password_changed
        })
        
        return success_response(data={
            "access_token": access_token,
            "token_type": "bearer",
            "employee": current_employee,
            "password_changed": password_changed
        })
    except Exception as e:
        return handle_generic_exception(e)

@router.post("/forgot-password", response_model=StandardResponse[dict])
async def forgot_password(email: str = Body(...)):
    """Initiates the password reset process."""
    return await reset_password_request(email)

@router.get("/verify-token", response_model=StandardResponse[dict])
async def verify_token(current_employee: Dict[str, Any] = Depends(get_current_employee_full)):
    """Used by the frontend to verify if the token is still valid."""
    # Get the token from the request
    token = await oauth2_scheme(request)
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        password_changed = payload.get("password_changed", True)
        
        return success_response(data={
            "valid": True,
            "employee_id": current_employee.get("id"),
            "store_id": current_employee.get("store_id"),
            "expires_in": ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            "password_changed": password_changed
        })
    except jwt.ExpiredSignatureError:
        return success_response(data={
            "valid": False,
            "message": "Token expired"
        })
    except jwt.JWTError:
        return success_response(data={
            "valid": False,
            "message": "Invalid token"
        })

@router.get("/health")
async def auth_health_check():
    """Health check for the authentication service."""
    return success_response(data={"status": "healthy", "module": "auth"})
