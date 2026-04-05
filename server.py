from dotenv import load_dotenv
from pathlib import Path

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

from fastapi import FastAPI, APIRouter, HTTPException, Request, Response, Depends
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import bcrypt
import jwt
import secrets
import aiosmtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import math
from bson import ObjectId

# MongoDB connection - with fallback for Railway
mongo_url = os.environ.get('MONGO_URL', os.environ.get('MONGODB_URL', 'mongodb://localhost:27017'))
db_name = os.environ.get('DB_NAME', 'gramamitra')
client = AsyncIOMotorClient(mongo_url)
db = client[db_name]

# Create the main app
app = FastAPI()

# Get allowed origins from environment or use defaults
FRONTEND_URL = os.environ.get("FRONTEND_URL", "")
ALLOWED_ORIGINS = [
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Add frontend URL if provided
if FRONTEND_URL:
    ALLOWED_ORIGINS.append(FRONTEND_URL)

# Custom CORS middleware to handle dynamic origins with credentials
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

class DynamicCORSMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        origin = request.headers.get("origin", "")
        
        # Handle preflight requests
        if request.method == "OPTIONS":
            response = Response(status_code=200)
        else:
            response = await call_next(request)
        
        # Allow the specific origin that made the request
        # This is safe because we're explicitly setting the origin from the request
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
            response.headers["Access-Control-Allow-Credentials"] = "true"
            response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, PATCH, OPTIONS"
            req_headers = request.headers.get("access-control-request-headers", "")
            response.headers["Access-Control-Allow-Headers"] = req_headers if req_headers else "Content-Type, Authorization, X-Requested-With, bypass-tunnel-reminder, ngrok-skip-browser-warning"
            response.headers["Access-Control-Max-Age"] = "86400"
        
        return response

app.add_middleware(DynamicCORSMiddleware)

# Create a router with the /api prefix
api_router = APIRouter(prefix="/api")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# JWT Configuration
JWT_ALGORITHM = "HS256"

def get_jwt_secret() -> str:
    return os.environ.get("JWT_SECRET", "default_secret")

def create_access_token(user_id: str, email: str) -> str:
    payload = {
        "sub": user_id,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(minutes=60),
        "type": "access"
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

def create_refresh_token(user_id: str) -> str:
    payload = {
        "sub": user_id,
        "exp": datetime.now(timezone.utc) + timedelta(days=7),
        "type": "refresh"
    }
    return jwt.encode(payload, get_jwt_secret(), algorithm=JWT_ALGORITHM)

# Password hashing
def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
    return hashed.decode("utf-8")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return bcrypt.checkpw(plain_password.encode("utf-8"), hashed_password.encode("utf-8"))

# Auth helper
async def get_current_user(request: Request) -> dict:
    token = request.cookies.get("access_token")
    if not token:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated")
    try:
        payload = jwt.decode(token, get_jwt_secret(), algorithms=[JWT_ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(status_code=401, detail="Invalid token type")
        user = await db.users.find_one({"_id": ObjectId(payload["sub"])})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        user["_id"] = str(user["_id"])
        user.pop("password_hash", None)
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")

# Email OTP
async def send_otp_email(email: str, otp: str):
    message = MIMEMultipart("alternative")
    message["Subject"] = "GramaMitra - Your OTP Code | మీ OTP కోడ్"
    message["From"] = os.environ.get("SMTP_USER")
    message["To"] = email
    
    html = f"""
    <html>
    <body style="font-family: Arial, sans-serif; padding: 20px;">
        <h2 style="color: #059669;">GramaMitra - గ్రామ మిత్ర</h2>
        <p>Your verification code is / మీ వెరిఫికేషన్ కోడ్:</p>
        <h1 style="color: #2563EB; font-size: 36px; letter-spacing: 5px;">{otp}</h1>
        <p>This code expires in 10 minutes / ఈ కోడ్ 10 నిమిషాలలో ముగుస్తుంది</p>
        <p style="color: #666;">If you didn't request this, please ignore / మీరు అభ్యర్థించకపోతే, దయచేసి విస్మరించండి</p>
    </body>
    </html>
    """
    message.attach(MIMEText(html, "html"))
    
    try:
        await aiosmtplib.send(
            message,
            hostname=os.environ.get("SMTP_HOST", "smtp.gmail.com"),
            port=int(os.environ.get("SMTP_PORT", "587")),
            username=os.environ.get("SMTP_USER"),
            password=os.environ.get("SMTP_PASSWORD"),
            start_tls=True
        )
        logger.info(f"OTP sent to {email}")
        return True
    except Exception as e:
        logger.error(f"Failed to send OTP: {e}")
        return False

# Pydantic Models
class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str
    phone: str
    area: Optional[str] = ""

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class OTPVerify(BaseModel):
    email: EmailStr
    otp: str

class OTPRequest(BaseModel):
    email: EmailStr

class UserUpdate(BaseModel):
    name: Optional[str] = None
    phone: Optional[str] = None
    area: Optional[str] = None

class ChangePassword(BaseModel):
    current_password: str
    new_password: str

class ChangeEmail(BaseModel):
    new_email: EmailStr
    password: str  # confirm password before changing email

class JobCreate(BaseModel):
    title: str
    description: str
    wage: str
    location: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    date: Optional[str] = None
    voiceTranscript: Optional[str] = None
    voiceRecording: Optional[str] = None  # Base64

class JobUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    wage: Optional[str] = None
    location: Optional[str] = None
    date: Optional[str] = None
    recruitmentClosed: Optional[bool] = None

class ApplicationStatusUpdate(BaseModel):
    status: str  # "accepted" | "rejected" | "pending"

class ApplicationCreate(BaseModel):
    jobId: str
    phone: str
    email: EmailStr
    area: str
    bio: Optional[str] = None
class VoiceProcessRequest(BaseModel):
    transcript: str
    language: str = "english"

class UserResponse(BaseModel):
    id: str
    name: str
    email: str
    phone: str
    area: str
    role: str
    email_verified: bool

class JobResponse(BaseModel):
    id: str
    title: str
    description: str
    wage: str
    location: str
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    date: str
    createdBy: str
    createdByName: str
    createdAt: str
    applicantCount: int = 0

class ApplicationResponse(BaseModel):
    id: str
    jobId: str
    jobTitle: str
    userId: str
    userName: str
    phone: str
    email: str
    area: str
    appliedAt: str
    status: str

class MessageCreate(BaseModel):
    content: str
    receiverId: str

class MessageResponse(BaseModel):
    id: str
    applicationId: str
    senderId: str
    receiverId: str
    content: str
    timestamp: str

# Distance calculation (Haversine formula)
def calculate_distance(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    R = 6371  # Earth's radius in km
    lat1_rad = math.radians(lat1)
    lat2_rad = math.radians(lat2)
    delta_lat = math.radians(lat2 - lat1)
    delta_lon = math.radians(lon2 - lon1)
    
    a = math.sin(delta_lat/2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    
    return R * c

# Auth Routes
@api_router.post("/auth/register")
async def register(user_data: UserCreate, response: Response):
    email = user_data.email.lower()
    existing = await db.users.find_one({"email": email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    user_doc = {
        "name": user_data.name,
        "email": email,
        "password_hash": hash_password(user_data.password),
        "phone": user_data.phone,
        "area": user_data.area or "",
        "role": "user",
        "email_verified": False,
        "otp": otp,
        "otp_expires": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat(),
        "created_at": datetime.now(timezone.utc).isoformat()
    }
    
    await db.users.insert_one(user_doc)
    
    # Send OTP
    await send_otp_email(email, otp)
    
    return {"message": "Registration successful. Please verify your email.", "email": email}

@api_router.post("/auth/verify-otp")
async def verify_otp(data: OTPVerify, response: Response):
    email = data.email.lower()
    user = await db.users.find_one({"email": email})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.get("email_verified"):
        raise HTTPException(status_code=400, detail="Email already verified")
    
    if user.get("otp") != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    otp_expires = user.get("otp_expires")
    if otp_expires:
        # Handle both datetime object and ISO string
        if isinstance(otp_expires, str):
            otp_expires = datetime.fromisoformat(otp_expires.replace('Z', '+00:00'))
        # Make sure otp_expires is timezone aware
        if otp_expires.tzinfo is None:
            otp_expires = otp_expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > otp_expires:
            raise HTTPException(status_code=400, detail="OTP expired")
    
    await db.users.update_one(
        {"email": email},
        {"$set": {"email_verified": True}, "$unset": {"otp": "", "otp_expires": ""}}
    )
    
    user_id = str(user["_id"])
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax", max_age=3600, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, samesite="lax", max_age=604800, path="/")
    
    return {
        "id": user_id,
        "name": user["name"],
        "email": user["email"],
        "phone": user["phone"],
        "area": user.get("area", ""),
        "role": user["role"],
        "email_verified": True
    }

@api_router.post("/auth/resend-otp")
async def resend_otp(data: OTPRequest):
    email = data.email.lower()
    user = await db.users.find_one({"email": email})
    
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if user.get("email_verified"):
        raise HTTPException(status_code=400, detail="Email already verified")
    
    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    await db.users.update_one(
        {"email": email},
        {"$set": {"otp": otp, "otp_expires": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()}}
    )
    
    await send_otp_email(email, otp)
    
    return {"message": "OTP sent successfully"}

@api_router.post("/auth/login")
async def login(user_data: UserLogin, response: Response):
    email = user_data.email.lower()
    user = await db.users.find_one({"email": email})
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not verify_password(user_data.password, user["password_hash"]):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not user.get("email_verified"):
        # Send new OTP
        otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
        await db.users.update_one(
            {"email": email},
            {"$set": {"otp": otp, "otp_expires": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()}}
        )
        await send_otp_email(email, otp)
        raise HTTPException(status_code=403, detail="Email not verified. OTP sent to your email.")
    
    user_id = str(user["_id"])
    access_token = create_access_token(user_id, email)
    refresh_token = create_refresh_token(user_id)
    
    response.set_cookie(key="access_token", value=access_token, httponly=True, secure=False, samesite="lax", max_age=3600, path="/")
    response.set_cookie(key="refresh_token", value=refresh_token, httponly=True, secure=False, samesite="lax", max_age=604800, path="/")
    
    return {
        "id": user_id,
        "name": user["name"],
        "email": user["email"],
        "phone": user["phone"],
        "area": user.get("area", ""),
        "role": user["role"],
        "email_verified": user.get("email_verified", False)
    }

@api_router.post("/auth/logout")
async def logout(response: Response):
    response.delete_cookie("access_token", path="/")
    response.delete_cookie("refresh_token", path="/")
    return {"message": "Logged out successfully"}

@api_router.get("/auth/me")
async def get_me(request: Request):
    user = await get_current_user(request)
    return user

class ForgotPasswordRequest(BaseModel):
    email: EmailStr

@api_router.post("/auth/forgot-password")
async def forgot_password(data: ForgotPasswordRequest):
    user = await db.users.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    await db.users.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "reset_otp": otp,
            "reset_otp_expires": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        }}
    )
    
    await send_otp_email(data.email, otp)
    return {"message": "OTP sent successfully"}

class ResetPasswordRequest(BaseModel):
    email: EmailStr
    otp: str
    new_password: str

@api_router.post("/auth/reset-password")
async def reset_password(data: ResetPasswordRequest):
    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
        
    user = await db.users.find_one({"email": data.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
        
    if user.get("reset_otp") != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
        
    otp_expires = user.get("reset_otp_expires")
    if not otp_expires:
        raise HTTPException(status_code=400, detail="OTP expired or invalid")
        
    if isinstance(otp_expires, str):
        otp_expires = datetime.fromisoformat(otp_expires.replace('Z', '+00:00'))
    if otp_expires.tzinfo is None:
        otp_expires = otp_expires.replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) > otp_expires:
        raise HTTPException(status_code=400, detail="OTP expired")
        
    hashed_pw = hash_password(data.new_password)
    await db.users.update_one(
        {"_id": user["_id"]},
        {
            "$set": {"password_hash": hashed_pw},
            "$unset": {"reset_otp": "", "reset_otp_expires": ""}
        }
    )
    
    return {"message": "Password reset successfully"}

# Profile Routes
@api_router.put("/profile")
async def update_profile(data: UserUpdate, request: Request):
    user = await get_current_user(request)
    
    update_data = {}
    if data.name:
        update_data["name"] = data.name
    if data.phone:
        update_data["phone"] = data.phone
    if data.area is not None:
        update_data["area"] = data.area
    
    if update_data:
        await db.users.update_one(
            {"_id": ObjectId(user["_id"])},
            {"$set": update_data}
        )
    
    updated_user = await db.users.find_one({"_id": ObjectId(user["_id"])}, {"password_hash": 0, "_id": 0})
    updated_user["id"] = user["_id"]
    return updated_user

# Change Password Route
@api_router.put("/profile/change-password")
async def change_password(data: ChangePassword, request: Request):
    user = await get_current_user(request)
    full_user = await db.users.find_one({"_id": ObjectId(user["_id"])})
    
    if not verify_password(data.current_password, full_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    
    if len(data.new_password) < 6:
        raise HTTPException(status_code=400, detail="New password must be at least 6 characters")
    
    await db.users.update_one(
        {"_id": ObjectId(user["_id"])},
        {"$set": {"password_hash": hash_password(data.new_password)}}
    )
    return {"message": "Password changed successfully"}

# Change Email Route
@api_router.put("/profile/change-email")
async def change_email(data: ChangeEmail, request: Request, response: Response):
    user = await get_current_user(request)
    full_user = await db.users.find_one({"_id": ObjectId(user["_id"])})
    
    if not verify_password(data.password, full_user["password_hash"]):
        raise HTTPException(status_code=400, detail="Password is incorrect")
    
    new_email = data.new_email.lower()
    
    # Check if email already in use
    existing = await db.users.find_one({"email": new_email})
    if existing and str(existing["_id"]) != user["_id"]:
        raise HTTPException(status_code=400, detail="Email already in use")
    
    # Generate OTP for new email verification
    otp = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
    
    await db.users.update_one(
        {"_id": ObjectId(user["_id"])},
        {"$set": {
            "pending_email": new_email,
            "pending_email_otp": otp,
            "pending_email_otp_expires": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()
        }}
    )
    
    await send_otp_email(new_email, otp)
    return {"message": "OTP sent to new email. Please verify to complete email change."}

# Verify new email OTP
@api_router.post("/profile/verify-email-change")
async def verify_email_change(data: OTPVerify, request: Request):
    user = await get_current_user(request)
    full_user = await db.users.find_one({"_id": ObjectId(user["_id"])})
    
    pending_email = full_user.get("pending_email")
    if not pending_email or pending_email != data.email.lower():
        raise HTTPException(status_code=400, detail="No pending email change for this email")
    
    if full_user.get("pending_email_otp") != data.otp:
        raise HTTPException(status_code=400, detail="Invalid OTP")
    
    otp_expires = full_user.get("pending_email_otp_expires")
    if otp_expires:
        if isinstance(otp_expires, str):
            otp_expires = datetime.fromisoformat(otp_expires.replace('Z', '+00:00'))
        if otp_expires.tzinfo is None:
            otp_expires = otp_expires.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > otp_expires:
            raise HTTPException(status_code=400, detail="OTP expired")
    
    await db.users.update_one(
        {"_id": ObjectId(user["_id"])},
        {
            "$set": {"email": pending_email, "email_verified": True},
            "$unset": {"pending_email": "", "pending_email_otp": "", "pending_email_otp_expires": ""}
        }
    )
    return {"message": "Email changed successfully", "email": pending_email}


@api_router.post("/jobs")
async def create_job(job_data: JobCreate, request: Request):
    user = await get_current_user(request)
    
    job_doc = {
        "title": job_data.title,
        "description": job_data.description,
        "wage": job_data.wage,
        "location": job_data.location,
        "latitude": job_data.latitude,
        "longitude": job_data.longitude,
        "date": job_data.date or datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        "createdBy": user["_id"],
        "createdByName": user["name"],
        "voiceTranscript": job_data.voiceTranscript,
        "voiceRecording": job_data.voiceRecording,
        "createdAt": datetime.now(timezone.utc).isoformat()
    }
    
    result = await db.jobs.insert_one(job_doc)
    job_doc["id"] = str(result.inserted_id)
    job_doc.pop("_id", None)
    job_doc["applicantCount"] = 0
    
    return job_doc

@api_router.get("/jobs")
async def get_jobs(
    search: Optional[str] = None,
    min_wage: Optional[int] = None,
    max_wage: Optional[int] = None,
    distance: Optional[int] = None,
    lat: Optional[float] = None,
    lng: Optional[float] = None,
    sort: Optional[str] = "newest"
):
    query = {}
    
    if search:
        query["$or"] = [
            {"title": {"$regex": search, "$options": "i"}},
            {"description": {"$regex": search, "$options": "i"}},
            {"location": {"$regex": search, "$options": "i"}}
        ]
    
    sort_order = -1 if sort == "newest" else 1
    
    jobs_cursor = db.jobs.find(query, {"_id": 1, "title": 1, "description": 1, "wage": 1, "location": 1, "latitude": 1, "longitude": 1, "date": 1, "createdBy": 1, "createdByName": 1, "createdAt": 1}).sort("createdAt", sort_order)
    jobs = await jobs_cursor.to_list(100)
    
    result = []
    for job in jobs:
        # Filter by wage
        try:
            wage_value = int(''.join(filter(str.isdigit, job.get("wage", "0"))))
            if min_wage and wage_value < min_wage:
                continue
            if max_wage and wage_value > max_wage:
                continue
        except:
            pass
        
        # Filter by distance
        if distance and lat and lng and job.get("latitude") and job.get("longitude"):
            job_distance = calculate_distance(lat, lng, job["latitude"], job["longitude"])
            if job_distance > distance:
                continue
            job["distance"] = round(job_distance, 1)
        
        # Get applicant count
        app_count = await db.applications.count_documents({"jobId": str(job["_id"])})
        
        result.append({
            "id": str(job["_id"]),
            "title": job["title"],
            "description": job["description"],
            "wage": job["wage"],
            "location": job["location"],
            "latitude": job.get("latitude"),
            "longitude": job.get("longitude"),
            "date": job.get("date", ""),
            "createdBy": job["createdBy"],
            "createdByName": job.get("createdByName", "Unknown"),
            "createdAt": job.get("createdAt", ""),
            "applicantCount": app_count,
            "distance": job.get("distance")
        })
    
    return result

@api_router.get("/jobs/{job_id}")
async def get_job(job_id: str):
    try:
        job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    except:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    app_count = await db.applications.count_documents({"jobId": job_id})
    
    return {
        "id": str(job["_id"]),
        "title": job["title"],
        "description": job["description"],
        "wage": job["wage"],
        "location": job["location"],
        "latitude": job.get("latitude"),
        "longitude": job.get("longitude"),
        "date": job.get("date", ""),
        "createdBy": job["createdBy"],
        "createdByName": job.get("createdByName", "Unknown"),
        "createdAt": job.get("createdAt", ""),
        "applicantCount": app_count
    }

@api_router.put("/jobs/{job_id}")
async def update_job(job_id: str, job_data: JobUpdate, request: Request):
    user = await get_current_user(request)
    
    try:
        job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    except:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job["createdBy"] != user["_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    update_data = {}
    if job_data.title:
        update_data["title"] = job_data.title
    if job_data.description:
        update_data["description"] = job_data.description
    if job_data.wage:
        update_data["wage"] = job_data.wage
    if job_data.location:
        update_data["location"] = job_data.location
    if job_data.date:
        update_data["date"] = job_data.date
    if job_data.recruitmentClosed is not None:
        update_data["recruitmentClosed"] = job_data.recruitmentClosed
    
    if update_data:
        await db.jobs.update_one({"_id": ObjectId(job_id)}, {"$set": update_data})
    
    return {"message": "Job updated successfully"}

@api_router.delete("/jobs/{job_id}")
async def delete_job(job_id: str, request: Request):
    user = await get_current_user(request)
    
    try:
        job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    except:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job["createdBy"] != user["_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    await db.jobs.delete_one({"_id": ObjectId(job_id)})
    await db.applications.delete_many({"jobId": job_id})
    
    return {"message": "Job deleted successfully"}

@api_router.get("/my-jobs")
async def get_my_jobs(request: Request):
    user = await get_current_user(request)
    
    jobs_cursor = db.jobs.find({"createdBy": user["_id"]}, {"_id": 1, "title": 1, "description": 1, "wage": 1, "location": 1, "date": 1, "createdAt": 1, "recruitmentClosed": 1}).sort("createdAt", -1)
    jobs = await jobs_cursor.to_list(100)
    
    result = []
    for job in jobs:
        app_count = await db.applications.count_documents({"jobId": str(job["_id"])})
        result.append({
            "id": str(job["_id"]),
            "title": job["title"],
            "description": job["description"],
            "wage": job["wage"],
            "location": job["location"],
            "date": job.get("date", ""),
            "createdAt": job.get("createdAt", ""),
            "applicantCount": app_count,
            "recruitmentClosed": job.get("recruitmentClosed", False)
        })
    
    return result

# Application Status Update
@api_router.patch("/applications/{app_id}/status")
async def update_application_status(app_id: str, data: ApplicationStatusUpdate, request: Request):
    user = await get_current_user(request)
    
    if data.status not in ["accepted", "rejected", "pending"]:
        raise HTTPException(status_code=400, detail="Invalid status")
    
    try:
        app = await db.applications.find_one({"_id": ObjectId(app_id)})
    except:
        raise HTTPException(status_code=404, detail="Application not found")
    
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
    
    # Verify the caller owns the job
    try:
        job = await db.jobs.find_one({"_id": ObjectId(app["jobId"])})
    except:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if not job or job["createdBy"] != user["_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    await db.applications.update_one(
        {"_id": ObjectId(app_id)},
        {"$set": {"status": data.status}}
    )
    
    return {"message": f"Application {data.status}"}

# Application Routes
@api_router.post("/applications")
async def apply_for_job(app_data: ApplicationCreate, request: Request):
    user = await get_current_user(request)
    
    # Check if job exists
    try:
        job = await db.jobs.find_one({"_id": ObjectId(app_data.jobId)})
    except:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    # Check if already applied
    existing = await db.applications.find_one({
        "jobId": app_data.jobId,
        "userId": user["_id"]
    })
    
    if existing:
        raise HTTPException(status_code=400, detail="Already applied for this job")
    
    app_doc = {
        "jobId": app_data.jobId,
        "jobTitle": job["title"],
        "userId": user["_id"],
        "userName": user["name"],
        "phone": app_data.phone,
        "email": app_data.email,
        "area": app_data.area,
        "bio": app_data.bio,
        "status": "pending",
        "appliedAt": datetime.now(timezone.utc).isoformat()
    }
    
    result = await db.applications.insert_one(app_doc)
    app_doc["id"] = str(result.inserted_id)
    app_doc.pop("_id", None)
    
    return app_doc

@api_router.get("/my-applications")
async def get_my_applications(request: Request):
    user = await get_current_user(request)
    
    apps_cursor = db.applications.find({"userId": user["_id"]}).sort("appliedAt", -1)
    apps = await apps_cursor.to_list(100)
    
    result = []
    for app in apps:
        job = await db.jobs.find_one({"_id": ObjectId(app["jobId"])})
        job_creator_id = job["createdBy"] if job else ""
        job_creator_name = job.get("createdByName", "Provider") if job else "Provider"
        
        result.append({
            "id": str(app["_id"]),
            "jobId": app["jobId"],
            "jobTitle": app.get("jobTitle", ""),
            "userId": app["userId"],
            "userName": app.get("userName", ""),
            "phone": app["phone"],
            "email": app["email"],
            "area": app["area"],
            "status": app.get("status", "pending"),
            "appliedAt": app.get("appliedAt", ""),
            "jobCreatorId": str(job_creator_id) if job_creator_id else "",
            "jobCreatorName": job_creator_name
        })
    
    return result

@api_router.get("/job-applicants/{job_id}")
async def get_job_applicants(job_id: str, request: Request):
    user = await get_current_user(request)
    
    # Verify job ownership
    try:
        job = await db.jobs.find_one({"_id": ObjectId(job_id)})
    except:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
    
    if job["createdBy"] != user["_id"]:
        raise HTTPException(status_code=403, detail="Not authorized")
    
    apps_cursor = db.applications.find({"jobId": job_id}).sort("appliedAt", -1)
    apps = await apps_cursor.to_list(100)
    
    result = []
    for app in apps:
        result.append({
            "id": str(app["_id"]),
            "jobId": app["jobId"],
            "jobTitle": app.get("jobTitle", ""),
            "userId": app["userId"],
            "userName": app.get("userName", ""),
            "phone": app["phone"],
            "email": app["email"],
            "area": app["area"],
            "status": app.get("status", "pending"),
            "appliedAt": app.get("appliedAt", "")
        })
    
    return result

# Chat/Messaging Routes
@api_router.get("/chats/active")
async def get_active_chats(request: Request):
    user = await get_current_user(request)
    
    user_jobs_cursor = db.jobs.find({"createdBy": user["_id"]})
    user_jobs = await user_jobs_cursor.to_list(1000)
    user_job_ids = [str(job["_id"]) for job in user_jobs]
    
    apps_cursor = db.applications.find({
        "status": "accepted",
        "$or": [
            {"userId": user["_id"]},
            {"jobId": {"$in": user_job_ids}}
        ]
    })
    apps = await apps_cursor.to_list(1000)
    
    result = []
    for app in apps:
        job = await db.jobs.find_one({"_id": ObjectId(app["jobId"])})
        if not job:
            continue
            
        is_applicant = (app["userId"] == user["_id"])
        recipient_id = job["createdBy"] if is_applicant else app["userId"]
        recipient_name = job.get("createdByName", "Job Provider") if is_applicant else app.get("userName", "Applicant")
        
        latest_msg = await db.messages.find_one(
            {"applicationId": str(app["_id"])}, 
            sort=[("timestamp", -1)]
        )
        
        result.append({
            "applicationId": str(app["_id"]),
            "jobId": str(job["_id"]),
            "jobTitle": job.get("title", ""),
            "recipientId": recipient_id,
            "recipientName": recipient_name,
            "isApplicant": is_applicant,
            "latestMessage": latest_msg["content"] if latest_msg else "",
            "latestMessageTime": latest_msg["timestamp"] if latest_msg else app.get("appliedAt", "")
        })
        
    result.sort(key=lambda x: x["latestMessageTime"], reverse=True)
    return result
@api_router.get("/applications/{app_id}/messages")
async def get_messages(app_id: str, request: Request):
    user = await get_current_user(request)
    
    # Verify user has access to this application
    try:
        app = await db.applications.find_one({"_id": ObjectId(app_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Application not found")
        
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
        
    job = await db.jobs.find_one({"_id": ObjectId(app["jobId"])})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
        
    if user["_id"] != app["userId"] and user["_id"] != job["createdBy"]:
        raise HTTPException(status_code=403, detail="Not authorized to view these messages")
        
    messages_cursor = db.messages.find({"applicationId": app_id}).sort("timestamp", 1)
    messages = await messages_cursor.to_list(1000)
    
    result = []
    for msg in messages:
        result.append({
            "id": str(msg["_id"]),
            "applicationId": msg["applicationId"],
            "senderId": msg["senderId"],
            "receiverId": msg["receiverId"],
            "content": msg["content"],
            "timestamp": msg.get("timestamp", "")
        })
        
    return result

@api_router.post("/applications/{app_id}/messages")
async def send_message(app_id: str, data: MessageCreate, request: Request):
    user = await get_current_user(request)
    
    # Verify user has access to this application
    try:
        app = await db.applications.find_one({"_id": ObjectId(app_id)})
    except Exception:
        raise HTTPException(status_code=404, detail="Application not found")
        
    if not app:
        raise HTTPException(status_code=404, detail="Application not found")
        
    job = await db.jobs.find_one({"_id": ObjectId(app["jobId"])})
    if not job:
        raise HTTPException(status_code=404, detail="Job not found")
        
    # Check if user is either applicant or job creator
    if user["_id"] != app["userId"] and user["_id"] != job["createdBy"]:
        raise HTTPException(status_code=403, detail="Not authorized to send messages here")
        
    msg_doc = {
        "applicationId": app_id,
        "senderId": user["_id"],
        "receiverId": data.receiverId,
        "content": data.content,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    
    result = await db.messages.insert_one(msg_doc)
    msg_doc["id"] = str(result.inserted_id)
    msg_doc.pop("_id", None)
    
    return msg_doc

# Voice Processing with Gemini
@api_router.post("/voice/process")
async def process_voice(data: VoiceProcessRequest, request: Request):
    # Authenticate user (user data not needed, but authentication required)
    await get_current_user(request)
    
    try:
        import google.generativeai as genai
        
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            raise HTTPException(status_code=500, detail="Gemini API key not configured")
        
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        system_prompt = """You are a job details extractor for rural India. Extract job posting details from the given text which may be in Telugu or English.
        
IMPORTANT: Return ONLY a valid JSON object with NO additional text, explanation, or markdown. The response must start with { and end with }.

Extract these fields:
- jobTitle: The job title/work type (string, e.g., "Farm Worker", "పొలం పని", "Construction Helper")
- description: Job description in the same language as input (string)
- wage: Payment/wage amount with rupee symbol (string, e.g., "₹500/day", "₹300/రోజు")
- location: Job location/village/area (string)
- date: Job date if mentioned (string, format YYYY-MM-DD), or today's date if not specified

If a field is unclear, make a reasonable inference from context. Always provide all fields."""
        
        prompt = f"{system_prompt}\n\nExtract job details from this {data.language} text and return ONLY JSON:\n\n{data.transcript}"
        
        response = model.generate_content(prompt)
        response_text = response.text
        logger.info(f"Gemini response: {response_text}")
        
        # Parse JSON from response
        try:
            # Clean response - remove markdown code blocks if present
            clean_response = response_text.strip()
            if clean_response.startswith("```"):
                # Extract content between code blocks
                parts = clean_response.split("```")
                if len(parts) >= 2:
                    clean_response = parts[1]
                    if clean_response.startswith("json"):
                        clean_response = clean_response[4:]
                    clean_response = clean_response.strip()
            
            # Find JSON object in response
            start_idx = clean_response.find('{')
            end_idx = clean_response.rfind('}')
            if start_idx != -1 and end_idx != -1:
                clean_response = clean_response[start_idx:end_idx+1]
            
            job_data = json.loads(clean_response)
            
            # Ensure all required fields exist
            job_data = {
                "jobTitle": job_data.get("jobTitle", ""),
                "description": job_data.get("description", data.transcript),
                "wage": job_data.get("wage", ""),
                "location": job_data.get("location", ""),
                "date": job_data.get("date", "")
            }
            
        except json.JSONDecodeError as e:
            logger.error(f"JSON parse error: {e}, response: {response_text}")
            # Fallback - use transcript as description
            job_data = {
                "jobTitle": "",
                "description": data.transcript,
                "wage": "",
                "location": "",
                "date": ""
            }
        
        return job_data
        
    except Exception as e:
        logger.error(f"Voice processing error: {e}")
        raise HTTPException(status_code=500, detail=f"Voice processing failed: {str(e)}")

class VoiceFormatRequest(BaseModel):
    field: str
    transcript: str
    language: str

@api_router.post("/voice/format")
async def format_voice_field(data: VoiceFormatRequest):
    if not data.transcript:
        return {"formatted": ""}
        
    try:
        import google.generativeai as genai
        
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return {"formatted": data.transcript}
        
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        today_str = datetime.now().strftime("%Y-%m-%d")
        
        system_prompt = f"You are a helpful formatting AI. Today's date is {today_str}. Output ONLY the formatted text."
        if data.field == "date":
            system_prompt += " The user provides a spoken date. Return exactly a 'YYYY-MM-DD' formatted string. For example, if they say 'tomorrow', calculate it."
        elif data.field == "wage":
            system_prompt += " The user provides a spoken wage or number. Extract only the digits (e.g. '500', '1000'). Remove any other text."
        elif data.field == "location_translate":
            if data.language == "te":
                system_prompt = "You are a specialized transliteration AI. The user provides a geographic location name in English. You MUST transliterate this name into ONLY pure Telugu script (తెలుగు). Do not output any English characters or formatting. Example: 'Hyderabad, Telangana' -> 'హైదరాబాద్, తెలంగాణ'. Reply with the localized text only."
            else:
                system_prompt += " Normalize the geographic text."
        else:
            system_prompt += " Normalize the text to be clean and grammatically correct."
        
        prompt = f"{system_prompt}\n\n{data.transcript}"
        response = model.generate_content(prompt)
        clean_response = response.text.strip()
        
        return {"formatted": clean_response}
    except Exception as e:
        logger.error(f"Voice formatting error: {e}")
        return {"formatted": data.transcript}

# Translation endpoint
class TranslateRequest(BaseModel):
    texts: List[str]
    target_language: str  # "english" or "telugu"

@api_router.post("/translate")
async def translate_texts(data: TranslateRequest):
    if not data.texts:
        return {"translations": []}
    
    target = "Telugu" if data.target_language == "telugu" else "English"
    
    try:
        import google.generativeai as genai
        
        api_key = os.environ.get("GEMINI_API_KEY")
        if not api_key:
            return {"translations": data.texts}
        
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel('gemini-1.5-flash')
        
        system_prompt = f"""You are a professional translator for a rural job marketplace app in India.
Translate the following texts to {target}.
- Keep proper nouns, place names, and rupee amounts (₹) unchanged.
- Return ONLY a valid JSON array of translated strings in the same order.
- Do NOT include any explanation or markdown."""
        
        texts_json = json.dumps(data.texts, ensure_ascii=False)
        prompt = f"{system_prompt}\n\nTranslate these texts to {target} and return ONLY a JSON array:\n{texts_json}"
        
        response = model.generate_content(prompt)
        response_text = response.text
        
        # Parse the JSON array
        clean = response_text.strip()
        if clean.startswith("```"):
            parts = clean.split("```")
            if len(parts) >= 2:
                clean = parts[1]
                if clean.startswith("json"):
                    clean = clean[4:]
                clean = clean.strip()
        
        start = clean.find('[')
        end = clean.rfind(']')
        if start != -1 and end != -1:
            clean = clean[start:end+1]
        
        translations = json.loads(clean)
        if not isinstance(translations, list):
            translations = data.texts
        
        return {"translations": translations}
    
    except Exception as e:
        logger.error(f"Translation error: {e}")
        # Return originals on failure
        return {"translations": data.texts}

# Dashboard Stats
@api_router.get("/dashboard/stats")
async def get_dashboard_stats(request: Request):
    user = await get_current_user(request)
    
    jobs_posted = await db.jobs.count_documents({"createdBy": user["_id"]})
    applications_received = 0
    
    # Count applications for user's jobs
    user_jobs = await db.jobs.find({"createdBy": user["_id"]}, {"_id": 1}).to_list(100)
    for job in user_jobs:
        count = await db.applications.count_documents({"jobId": str(job["_id"])})
        applications_received += count
    
    jobs_applied = await db.applications.count_documents({"userId": user["_id"]})
    
    # Get recent activity
    recent_jobs = await db.jobs.find({"createdBy": user["_id"]}).sort("createdAt", -1).limit(5).to_list(5)
    recent_apps = await db.applications.find({"userId": user["_id"]}).sort("appliedAt", -1).limit(5).to_list(5)
    
    return {
        "jobsPosted": jobs_posted,
        "applicationsReceived": applications_received,
        "jobsApplied": jobs_applied,
        "recentJobs": [{"id": str(j["_id"]), "title": j["title"], "date": j.get("createdAt", "")} for j in recent_jobs],
        "recentApplications": [{"id": str(a["_id"]), "jobTitle": a.get("jobTitle", ""), "status": a.get("status", "pending")} for a in recent_apps]
    }

# Health check
@api_router.get("/")
async def root():
    return {"message": "GramaMitra API is running"}

@api_router.get("/health")
async def health():
    return {"status": "healthy"}

# Include the router
app.include_router(api_router)

# Startup event
@app.on_event("startup")
async def startup_event():
    # Create indexes
    await db.users.create_index("email", unique=True)
    await db.jobs.create_index("createdBy")
    await db.applications.create_index([("jobId", 1), ("userId", 1)])
    
    # Seed admin (only if ADMIN_EMAIL and ADMIN_PASSWORD are set)
    admin_email = os.environ.get("ADMIN_EMAIL")
    admin_password = os.environ.get("ADMIN_PASSWORD")
    
    if admin_email and admin_password:
        existing = await db.users.find_one({"email": admin_email})
        
        if existing is None:
            await db.users.insert_one({
                "email": admin_email,
                "password_hash": hash_password(admin_password),
                "name": "Admin",
                "phone": "9999999999",
                "area": "Admin Area",
                "role": "admin",
                "email_verified": True,
                "created_at": datetime.now(timezone.utc).isoformat()
            })
            logger.info(f"Admin user created: {admin_email}")

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
