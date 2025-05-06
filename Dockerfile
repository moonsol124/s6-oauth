# Dockerfile for oauth-server

# Step 1: Base Image
FROM node:18-alpine As base

# Step 2: Working Directory
WORKDIR /app

# Step 3: Copy package files
COPY package*.json ./

# Step 4: Install production dependencies
# This service uses express-session, axios, uuid etc. - no special build tools needed
RUN npm ci --only=production

# Step 5: Copy application code
COPY . .

# Step 6: Expose the application port
# Your app uses process.env.PORT || 3000
EXPOSE 3000

# Step 7: Run command
# Assumes your main file is index.js
CMD ["node", "app.js"]