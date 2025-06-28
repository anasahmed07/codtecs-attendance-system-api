from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import pymongo
from datetime import datetime, timedelta
import jwt
import bcrypt
import secrets
import string
from calendar import monthrange
import os

app = FastAPI(title="Attendance System API", version="1.0.0")

# CORS middleware
# app.add_middleware(
#     CORSMiddleware,
#     allow_origins= os.getenv("CORS_ORIGINS").split(","),  # Admin and Employee dashboards
#     allow_credentials=True,
#     allow_methods=["*"],
#     allow_headers=["*"],
# )

@app.get("/")
def responder():
    # Return a OK response
    return {"message": "Fast api running properly","docs": "https://<url>.vercel.app/docs"}


# MongoDB connection
client = pymongo.MongoClient(os.getenv("MONGO_URI"))
db = client[os.getenv("DB_NAME")]
employees_collection = db["employees"]
attendance_collection = db["attendance"]
admins_collection = db["admins"]

# Security
security = HTTPBearer()

# Pydantic models
class Employee(BaseModel):
    employee_id: str
    name: str
    email: str
    department: str
    create_login: Optional[bool] = False

class EmployeeUpdate(BaseModel):
    name: Optional[str] = None
    email: Optional[str] = None
    department: Optional[str] = None

class AttendanceRecord(BaseModel):
    employee_id: str
    name: str
    check_in_time: datetime
    verification_method: str

class AttendanceUpdate(BaseModel):
    check_in_time: datetime
    verification_method: str

class AdminLogin(BaseModel):
    username: str
    password: str

class EmployeeLogin(BaseModel):
    employee_id: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str
    user_type: str
    user_info: dict

class PasswordReset(BaseModel):
    employee_id: str
    new_password: str

# Helper functions
def generate_password(length=8):
    """Generate a random password"""
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, os.getenv("JWT_SECRET_KEY"), algorithm=os.getenv("JWT_ALGORITHM"))
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, os.getenv("JWT_SECRET_KEY"), algorithms=[os.getenv("JWT_ALGORITHM")])
        username: str = payload.get("sub")
        user_type: str = payload.get("user_type")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return {"username": username, "user_type": user_type}
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials",
            headers={"WWW-Authenticate": "Bearer"},
        )

def verify_admin_token(current_user: dict = Depends(verify_token)):
    if current_user["user_type"] != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required"
        )
    return current_user["username"]

def verify_employee_token(current_user: dict = Depends(verify_token)):
    if current_user["user_type"] != "employee":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Employee access required"
        )
    return current_user["username"]

# Authentication endpoints
@app.post("/api/auth/admin/login", response_model=Token)
async def admin_login(admin_data: AdminLogin):
    admin = admins_collection.find_one({"username": admin_data.username})
    
    if not admin or not bcrypt.checkpw(admin_data.password.encode('utf-8'), admin['password'].encode('utf-8')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes= int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES")))
    access_token = create_access_token(
        data={"sub": admin_data.username, "user_type": "admin"}, 
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user_type": "admin",
        "user_info": {"username": admin_data.username}
    }

@app.post("/api/auth/employee/login", response_model=Token)
async def employee_login(employee_data: EmployeeLogin):
    employee = employees_collection.find_one({"employee_id": employee_data.employee_id})
    
    if not employee or "password" not in employee:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Employee not found or login not enabled",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    if not bcrypt.checkpw(employee_data.password.encode('utf-8'), employee['password'].encode('utf-8')):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect employee ID or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    access_token_expires = timedelta(minutes=int(os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES")))
    access_token = create_access_token(
        data={"sub": employee_data.employee_id, "user_type": "employee"}, 
        expires_delta=access_token_expires
    )
    return {
        "access_token": access_token, 
        "token_type": "bearer",
        "user_type": "employee",
        "user_info": {
            "employee_id": employee["employee_id"],
            "name": employee["name"],
            "email": employee["email"],
            "department": employee["department"]
        }
    }

# Admin endpoints (existing ones updated)
@app.get("/api/admin/employees", response_model=List[dict])
async def get_employees(current_user: str = Depends(verify_admin_token)):
    employees = list(employees_collection.find({}, {"password": 0}))  # Exclude password
    for employee in employees:
        employee["_id"] = str(employee["_id"])
        employee["has_login"] = "password" in employees_collection.find_one({"employee_id": employee["employee_id"]}, {"password": 1}) or {}
    return employees

@app.post("/api/admin/employees")
async def create_employee(employee: Employee, current_user: str = Depends(verify_admin_token)):
    # Check if employee already exists
    if employees_collection.find_one({"employee_id": employee.employee_id}):
        raise HTTPException(status_code=400, detail="Employee ID already exists")
    
    employee_data = employee.dict()
    del employee_data["create_login"]  # Remove this field from storage
    employee_data["created_at"] = datetime.now()
    employee_data["created_by"] = current_user
    
    # Generate login credentials if requested
    generated_password = None
    if employee.create_login:
        generated_password = generate_password()
        hashed_password = bcrypt.hashpw(generated_password.encode('utf-8'), bcrypt.gensalt())
        employee_data["password"] = hashed_password.decode('utf-8')  # Store as string
        employee_data["login_enabled"] = True
    
    result = employees_collection.insert_one(employee_data)
    
    response = {
        "message": "Employee created successfully", 
        "id": str(result.inserted_id),
        "employee_id": employee.employee_id
    }
    
    if generated_password:
        response["login_credentials"] = {
            "employee_id": employee.employee_id,
            "password": generated_password
        }
    
    return response

@app.put("/api/admin/employees/{employee_id}")
async def update_employee(employee_id: str, employee_update: EmployeeUpdate, 
                         current_user: str = Depends(verify_admin_token)):
    update_data = {k: v for k, v in employee_update.dict().items() if v is not None}
    update_data["updated_at"] = datetime.now()
    update_data["updated_by"] = current_user
    
    result = employees_collection.update_one(
        {"employee_id": employee_id}, 
        {"$set": update_data}
    )
    
    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    return {"message": "Employee updated successfully"}

@app.post("/api/admin/employees/{employee_id}/enable-login")
async def enable_employee_login(employee_id: str, current_user: str = Depends(verify_admin_token)):
    employee = employees_collection.find_one({"employee_id": employee_id})
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Generate password if not exists
    if "password" not in employee:
        generated_password = generate_password()
        hashed_password = bcrypt.hashpw(generated_password.encode('utf-8'), bcrypt.gensalt())
        
        employees_collection.update_one(
            {"employee_id": employee_id},
            {"$set": {
                "password": hashed_password.decode('utf-8'), # Store as string
                "login_enabled": True,
                "login_created_at": datetime.now(),
                "login_created_by": current_user
            }}
        )
        
        return {
            "message": "Login enabled for employee",
            "login_credentials": {
                "employee_id": employee_id,
                "password": generated_password
            }
        }
    else:
        return {"message": "Login already enabled for this employee"}

@app.post("/api/admin/employees/{employee_id}/reset-password")
async def reset_employee_password(employee_id: str, current_user: str = Depends(verify_admin_token)):
    employee = employees_collection.find_one({"employee_id": employee_id})
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    new_password = generate_password()
    hashed_password = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    
    employees_collection.update_one(
        {"employee_id": employee_id},
        {"$set": {
            "password": hashed_password.decode('utf-8'), # Store as string
            "password_reset_at": datetime.now(),
            "password_reset_by": current_user
        }}
    )
    
    return {
        "message": "Password reset successfully",
        "new_credentials": {
            "employee_id": employee_id,
            "password": new_password
        }
    }

@app.delete("/api/admin/employees/{employee_id}")
async def delete_employee(employee_id: str, current_user: str = Depends(verify_admin_token)):
    result = employees_collection.delete_one({"employee_id": employee_id})
    
    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Also delete attendance records
    attendance_collection.delete_many({"employee_id": employee_id})
    
    return {"message": "Employee deleted successfully"}

# Admin attendance endpoints
@app.get("/api/admin/attendance", response_model=List[dict])
async def get_all_attendance(
    date: Optional[str] = None,
    employee_id: Optional[str] = None,
    current_user: str = Depends(verify_admin_token)
):
    query = {}
    
    if date:
        try:
            target_date = datetime.strptime(date, "%Y-%m-%d")
            next_date = target_date + timedelta(days=1)
            query["check_in_time"] = {"$gte": target_date, "$lt": next_date}
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid date format. Use YYYY-MM-DD")
    
    if employee_id:
        query["employee_id"] = employee_id
    
    attendance_records = list(attendance_collection.find(query).sort("check_in_time", -1))
    
    for record in attendance_records:
        record["_id"] = str(record["_id"])
        record["check_in_time"] = record["check_in_time"].isoformat()
    
    return attendance_records

# Employee endpoints
@app.get("/api/employee/profile")
async def get_employee_profile(current_user: str = Depends(verify_employee_token)):
    employee = employees_collection.find_one({"employee_id": current_user}, {"password": 0})
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    employee["_id"] = str(employee["_id"])
    return employee

@app.get("/api/employee/attendance")
async def get_employee_attendance(
    month: Optional[int] = None,
    year: Optional[int] = None,
    current_user: str = Depends(verify_employee_token)
):
    # Default to current month if not specified
    if not month or not year:
        now = datetime.now()
        month = month or now.month
        year = year or now.year
    
    # Get first and last day of the month
    first_day = datetime(year, month, 1)
    last_day_num = monthrange(year, month)[1]
    last_day = datetime(year, month, last_day_num, 23, 59, 59)
    
    # Query attendance for the employee in the specified month
    attendance_records = list(attendance_collection.find({
        "employee_id": current_user,
        "check_in_time": {"$gte": first_day, "$lte": last_day}
    }).sort("check_in_time", 1))
    
    # Format records
    for record in attendance_records:
        record["_id"] = str(record["_id"])
        record["check_in_time"] = record["check_in_time"].isoformat()
        record["date"] = record["check_in_time"][:10]  # YYYY-MM-DD format
    
    # Calculate statistics
    total_days = last_day_num
    present_days = len(attendance_records)
    working_days = total_days - 8  # Assuming 8 weekends in a month (rough estimate)
    attendance_percentage = (present_days / working_days * 100) if working_days > 0 else 0
    
    return {
        "month": month,
        "year": year,
        "records": attendance_records,
        "statistics": {
            "total_days": total_days,
            "present_days": present_days,
            "working_days": working_days,
            "attendance_percentage": round(attendance_percentage, 2)
        }
    }

@app.get("/api/employee/qr-code")
async def get_employee_qr_code(current_user: str = Depends(verify_employee_token)):
    employee = employees_collection.find_one({"employee_id": current_user})
    if not employee:
        raise HTTPException(status_code=404, detail="Employee not found")
    
    # Generate QR code data
    import json
    qr_data = {
        "employee_id": employee["employee_id"],
        "name": employee["name"],
        "timestamp": datetime.now().isoformat()
    }
    
    return {
        "employee_id": employee["employee_id"],
        "name": employee["name"],
        "qr_data": json.dumps(qr_data)
    }

# Statistics endpoint (admin only)
@app.get("/api/admin/stats")
async def get_statistics(current_user: str = Depends(verify_admin_token)):
    total_employees = employees_collection.count_documents({})
    employees_with_login = employees_collection.count_documents({"password": {"$exists": True}})
    
    today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    tomorrow = today + timedelta(days=1)
    
    today_attendance = attendance_collection.count_documents({
        "check_in_time": {"$gte": today, "$lt": tomorrow}
    })
    
    # Get attendance rate for the last 7 days
    week_ago = today - timedelta(days=7)
    weekly_attendance = attendance_collection.count_documents({
        "check_in_time": {"$gte": week_ago, "$lt": tomorrow}
    })
    
    return {
        "total_employees": total_employees,
        "employees_with_login": employees_with_login,
        "today_attendance": today_attendance,
        "attendance_rate_today": round((today_attendance / total_employees * 100) if total_employees > 0 else 0, 2),
        "weekly_attendance": weekly_attendance
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("index:app", host="0.0.0.0", port=8000, reload=True)

def handler(request):
    return app(request)