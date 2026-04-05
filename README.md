# GramaMitra Backend

FastAPI backend for GramaMitra - Smart Rural Job Platform with Voice AI.

## Features

- JWT Authentication with email OTP verification
- User registration, login, logout
- Jobs CRUD (create, read, update, delete)
- Job applications system
- Voice processing with Gemini AI
- GPS-based distance calculation
- Dashboard statistics
- Telugu + English bilingual support

## Deployment on Railway

### 1. Create a new project on Railway

1. Go to [Railway](https://railway.app)
2. Click "New Project" → "Deploy from GitHub repo"
3. Select this repository

### 2. Add MongoDB

1. In Railway, click "New" → "Database" → "MongoDB"
2. Copy the `MONGO_URL` from the MongoDB service

### 3. Set Environment Variables

In Railway, go to your backend service → Variables → Add the following:

```
MONGO_URL=<your-mongodb-url-from-railway>
DB_NAME=gramamitra
JWT_SECRET=<generate-a-strong-secret-key>
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=<your-email@gmail.com>
SMTP_PASSWORD=<your-gmail-app-password>
GEMINI_API_KEY=<your-gemini-api-key>
FRONTEND_URL=<your-frontend-railway-url>
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=<secure-admin-password>
```

### 4. Deploy

Railway will automatically:
- Detect Python project
- Install dependencies from `requirements.txt`
- Run the Procfile command

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login
- `POST /api/auth/logout` - Logout
- `POST /api/auth/verify-otp` - Verify email OTP
- `POST /api/auth/resend-otp` - Resend OTP
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password
- `GET /api/auth/me` - Get current user

### Jobs
- `POST /api/jobs` - Create job
- `GET /api/jobs` - List jobs (with filters)
- `GET /api/jobs/{id}` - Get job details
- `PUT /api/jobs/{id}` - Update job
- `DELETE /api/jobs/{id}` - Delete job
- `GET /api/my-jobs` - Get user's posted jobs

### Applications
- `POST /api/applications` - Apply for job
- `GET /api/my-applications` - Get user's applications
- `GET /api/job-applicants/{jobId}` - Get job applicants
- `PATCH /api/applications/{id}/status` - Update application status

### Profile
- `PUT /api/profile` - Update profile
- `PUT /api/profile/change-password` - Change password
- `PUT /api/profile/change-email` - Request email change
- `POST /api/profile/verify-email-change` - Verify new email

### Voice AI
- `POST /api/voice/process` - Process voice transcript
- `POST /api/voice/format` - Format voice input
- `POST /api/translate` - Translate texts

### Dashboard
- `GET /api/dashboard/stats` - Get dashboard statistics

### Health
- `GET /api/health` - Health check
- `GET /api/` - API status

## Local Development

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env with your values

# Run server
uvicorn server:app --reload --port 8001
```
