# Dockerfile for the analytics API
FROM node:22-slim

# Set working directory
WORKDIR /usr/src/app

# Copy application code
COPY . .

# Expose application port
EXPOSE 3000

# Default command
CMD ["node", "server.js"]