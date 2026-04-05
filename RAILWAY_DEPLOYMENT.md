# Railway Deployment Guide for GramaMitra Backend

## Critical Fix for CORS Issues

This guide will help you properly configure the backend on Railway to fix CORS errors.

## Environment Variables Configuration

### Required Environment Variables

In your Railway backend project dashboard, go to **Variables** tab and set the following:

#### 1. FRONTEND_URL (CRITICAL for CORS)
```
FRONTEND_URL=https://gramina-frontend-production.up.railway.app
```
**Important:** Replace with your actual Railway frontend URL. This MUST match exactly.

#### 2. MongoDB Configuration
```
MONGO_URL=mongodb+srv://your-username:your-password@your-cluster.mongodb.net/?retryWrites=true&w=majority
DB_NAME=gramamitra
```

#### 3. JWT Configuration
```
JWT_SECRET=your_super_secure_random_string_here
```
Generate a strong random string for production.

#### 4. Optional: Admin Account
```
ADMIN_EMAIL=admin@gramamitra.com
ADMIN_PASSWORD=your_secure_password
```

#### 5. Optional: Gemini API (for voice features)
```
GEMINI_API_KEY=your_gemini_api_key
```

## Deployment Steps

### 1. Update Environment Variables in Railway Dashboard

1. Go to your Railway project dashboard
2. Click on your backend service
3. Navigate to the **Variables** tab
4. Add/update the `FRONTEND_URL` variable with your frontend's Railway URL
5. Ensure all other required variables are set

### 2. Redeploy the Service

After updating the environment variables:
1. Railway will automatically redeploy, OR
2. Manually trigger a redeploy from the Deployments tab
3. Wait for the deployment to complete

### 3. Verify CORS Configuration

The backend now includes an improved CORS middleware that:
- ✅ Properly handles preflight OPTIONS requests
- ✅ Returns correct Access-Control-Allow-Origin headers
- ✅ Supports credentials (cookies) for authentication
- ✅ Allows all necessary HTTP methods and headers

## Testing the Fix

1. Open your frontend URL: `https://gramina-frontend-production.up.railway.app`
2. Try to sign up with test credentials
3. Check browser console - the CORS error should be gone
4. Authentication should work properly

## Common Issues

### Issue: Still getting CORS errors

**Solution:**
1. Double-check that `FRONTEND_URL` in Railway matches your frontend URL exactly
2. Make sure there are no trailing slashes
3. Verify the backend has redeployed after setting the variable

### Issue: Backend not starting

**Solution:**
1. Check the Railway logs for error messages
2. Verify `MONGO_URL` is set correctly
3. Ensure all required environment variables are configured

### Issue: Authentication not working

**Solution:**
1. Ensure `JWT_SECRET` is set
2. Check that cookies are being sent (look for `access_token` in browser dev tools)
3. Verify backend logs for authentication errors

## Changes Made

### server.py Updates:
- ✅ Fixed CORS middleware to properly handle preflight requests
- ✅ Added explicit header handling for Railway deployments
- ✅ Improved OPTIONS request responses
- ✅ Added frontend URL to allowed origins list

## Support

If you continue to experience issues after following this guide:
1. Check Railway backend logs for errors
2. Check browser console for detailed error messages
3. Verify all environment variables are correctly set
4. Ensure both frontend and backend are using the latest code from GitHub
