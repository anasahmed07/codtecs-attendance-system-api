# Attendance System API

A FastAPI-based backend for managing employee attendance, authentication, and statistics. This API provides endpoints for both admin and employee roles, with JWT-based authentication and MongoDB as the data store.

## Features
- Admin and employee authentication (JWT)
- Employee management (CRUD, enable login, reset password)
- Attendance tracking and statistics
- CORS support for dashboard integration

## Requirements
- Python 3.13+
- MongoDB instance

## Installation

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   Or, if using [pyproject.toml]:
   ```bash
   pip install .
   ```

2. **Set up environment variables:**
   Create a `.env` file (or set these variables in your deployment environment):

   ```env
   # Example .env for Attendance System API
   MONGO_URI=mongodb+srv://<username>:<password>@<cluster-url>/<dbname>?retryWrites=true&w=majority
   DB_NAME=attendance_db
   JWT_SECRET_KEY=your_jwt_secret_key
   JWT_ALGORITHM=HS256
   JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
   CORS_ORIGINS=http://localhost:3000,http://localhost:8000
   ```
   - `MONGO_URI`: MongoDB connection string
   - `DB_NAME`: Database name
   - `JWT_SECRET_KEY`: Secret key for JWT signing
   - `JWT_ALGORITHM`: Algorithm for JWT (e.g., HS256)
   - `JWT_ACCESS_TOKEN_EXPIRE_MINUTES`: Token expiry in minutes
   - `CORS_ORIGINS`: Comma-separated list of allowed origins for CORS

3. **Run the API:**
   ```bash
   uvicorn index:app --host 0.0.0.0 --port 8000 --reload
   ```

## API Endpoints Overview

### Authentication
- `POST /api/auth/admin/login` — Admin login
- `POST /api/auth/employee/login` — Employee login

### Admin Endpoints (require admin JWT)
- `GET /api/admin/employees` — List all employees
- `POST /api/admin/employees` — Create a new employee
- `PUT /api/admin/employees/{employee_id}` — Update employee details
- `POST /api/admin/employees/{employee_id}/enable-login` — Enable login for employee
- `POST /api/admin/employees/{employee_id}/reset-password` — Reset employee password
- `DELETE /api/admin/employees/{employee_id}` — Delete employee and their attendance
- `GET /api/admin/attendance` — Get attendance records (filter by date/employee)
- `GET /api/admin/stats` — Get statistics (total employees, attendance rate, etc.)

### Employee Endpoints (require employee JWT)
- `GET /api/employee/profile` — Get employee profile
- `GET /api/employee/attendance` — Get attendance for a month/year
- `GET /api/employee/qr-code` — Get QR code data for check-in

## Example Usage

**Admin Login:**
```json
POST /api/auth/admin/login
{
  "username": "admin1",
  "password": "yourpassword"
}
```

**Employee Login:**
```json
POST /api/auth/employee/login
{
  "employee_id": "EMP001",
  "password": "employeepassword"
}
```

## Notes
- All protected endpoints require the `Authorization: Bearer <token>` header.
- For more details, see the OpenAPI docs at `/docs` when running the server.