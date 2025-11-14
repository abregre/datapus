# Datapus- Containerized File Upload Service

A production-ready, containerized Node.js/Express API for secure file uploads to AWS S3 with virus scanning, validation, and organized storage.

## Features

- ✅ **Secure File Uploads** - API key authentication
- ✅ **Virus Scanning** - Integrated ClamAV for malware detection
- ✅ **S3 Storage** - Automatic upload to AWS S3 with versioning
- ✅ **File Validation** - Type, size, and name validation
- ✅ **Organized Structure** - Hierarchical folder organization with tagging
- ✅ **Batch Uploads** - Support for multiple file uploads
- ✅ **Chunked Processing** - Handle large files efficiently
- ✅ **Docker Ready** - Fully containerized for easy deployment
- ✅ **Configurable** - All settings via environment variables
- ✅ **Production Ready** - Logging, error handling, health checks

## Table of Contents

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration](#configuration)
- [API Documentation](#api-documentation)
- [Deployment](#deployment)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Security](#security)

---

## Quick Start

### 1. Clone and Setup

```bash
git clone <repository-url>
cd file-api
cp .env.example .env
```

### 2. Configure Environment

Edit `.env` and add your AWS credentials:

```bash
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
S3_BUCKET_NAME=your-bucket-name
```

### 3. Deploy with Docker

```bash
docker-compose up -d
```

### 4. Get Your API Key

Check the logs for your generated API key:

```bash
docker-compose logs api | grep "API KEY"
```

### 5. Test Upload

```bash
curl -X POST http://localhost:3000/api/v1/upload \
  -H "X-API-Key: 3dcc8fe9a9c082019d9721c566488362aa14e3e739db3a1aafff14d2fe1767e4" \
  -F "file=@/path/to/test.pdf" \
  -F "source=test" \
  -F "tag=demo"
```

---

## Prerequisites

- Docker 20.x or higher
- Docker Compose 2.x or higher
- AWS S3 bucket with appropriate permissions
- (Optional) Domain name for production deployment

---

## Installation

### Option 1: Docker (Recommended)

```bash
# Start all services
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down

# Rebuild after code changes
docker-compose up -d --build
```

### Option 2: Local Development

```bash
# Install dependencies
npm install

# Start ClamAV separately (or disable virus scanning)
# Set ENABLE_VIRUS_SCAN=false in .env

# Start application
npm start

# Development mode with auto-reload
npm run dev
```

---

## Configuration

### Environment Variables Reference

| Variable                 | Default                             | Description                      |
| ------------------------ | ----------------------------------- | -------------------------------- |
| **Server**               |                                     |                                  |
| `PORT`                   | `3000`                              | API server port                  |
| `NODE_ENV`               | `production`                        | Environment mode                 |
| `API_KEY`                | auto-generated                      | API authentication key           |
| **AWS S3**               |                                     |                                  |
| `AWS_REGION`             | `us-east-1`                         | AWS region                       |
| `AWS_ACCESS_KEY_ID`      | -                                   | **Required**: AWS access key     |
| `AWS_SECRET_ACCESS_KEY`  | -                                   | **Required**: AWS secret key     |
| `S3_BUCKET_NAME`         | -                                   | **Required**: S3 bucket name     |
| `S3_ENDPOINT`            | -                                   | Custom S3 endpoint (MinIO, etc.) |
| **File Validation**      |                                     |                                  |
| `ALLOWED_FILE_TYPES`     | `pdf,jpg,jpeg,png,doc,docx,txt,zip` | Allowed file extensions          |
| `MAX_FILE_SIZE`          | `100MB`                             | Maximum size per file            |
| `MAX_REQUEST_SIZE`       | `500MB`                             | Maximum total request size       |
| **Virus Scanning**       |                                     |                                  |
| `ENABLE_VIRUS_SCAN`      | `true`                              | Enable/disable virus scanning    |
| `CLAMAV_HOST`            | `clamav`                            | ClamAV hostname                  |
| `CLAMAV_PORT`            | `3310`                              | ClamAV port                      |
| **Upload Settings**      |                                     |                                  |
| `ENABLE_VERSIONING`      | `true`                              | Enable S3 versioning             |
| `MULTIPART_CHUNK_SIZE`   | `5MB`                               | Chunk size for uploads           |
| `MAX_CONCURRENT_UPLOADS` | `5`                                 | Max concurrent batch uploads     |
| **Folder Structure**     |                                     |                                  |
| `DEFAULT_SOURCE_FOLDER`  | `uploads`                           | Default source folder name       |
| `TAG_SEPARATOR`          | `_`                                 | Separator for tags in paths      |

### File Size Format

File sizes support human-readable formats:

- `100MB` = 104,857,600 bytes
- `1.5GB` = 1,610,612,736 bytes
- `500KB` = 512,000 bytes
- `10B` = 10 bytes

---

## API Documentation

### Authentication

All API requests (except `/health`) require an API key in the header:

```
X-API-Key: your-api-key-here
```

### Base URL

```
http://localhost:3000/api/v1
```

---

### Endpoints

#### 1. Health Check

Check service health and connectivity.

**Endpoint:** `GET /health`

**Authentication:** None required

**Response:**

```json
{
  "status": "ok",
  "timestamp": "2025-11-14T10:30:00.000Z",
  "uptime": 3600.5,
  "checks": {
    "api": "ok",
    "s3": "ok",
    "virusScanner": "ok"
  }
}
```

**curl Example:**

```bash
curl http://localhost:3000/health
```

---

#### 2. Single File Upload

Upload a single file to S3.

**Endpoint:** `POST /api/v1/upload`

**Authentication:** Required

**Content-Type:** `multipart/form-data`

**Parameters:**

| Field    | Type   | Required | Description                        |
| -------- | ------ | -------- | ---------------------------------- |
| `file`   | file   | Yes      | File to upload                     |
| `source` | string | No       | Source folder (default: 'uploads') |
| `tag`    | string | No       | Tag subfolder (default: 'general') |
---

## Troubleshooting

### Common Issues

1. **Container won't start**
   - Check that all required environment variables are set (AWS credentials)
   - Verify that the ClamAV service is healthy before the API starts
   - Ensure you have valid AWS credentials with S3 permissions

2. **File upload fails**
   - Verify that the file type is in the ALLOWED_FILE_TYPES list
   - Check that the file size is within MAX_FILE_SIZE limits
   - Ensure virus scanning service is running if enabled

3. **API key not working**
   - Check the logs for the generated API key: `docker-compose logs api | grep "API KEY"`
   - Ensure the X-API-Key header is properly formatted
   - Verify the API key matches exactly (case-sensitive)

4. **S3 upload errors**
   - Confirm AWS credentials have proper S3 permissions
   - Verify the S3 bucket exists and is accessible
   - Check that the region matches your bucket's region

5. **Permission errors on cloud server**
   - The container runs as user 'nodejs' (UID 1001) but mounts host directories
   - If you get permission errors, fix ownership on the host system:
   
   ```bash
   # Fix permissions for data and logs directories
   sudo chown -R 1001:1001 data/
   sudo chown -R 1001:1001 logs/
   ```
   
   - Or run the container with matching user ID:
   
   ```bash
   # Set the container to run with your user ID
   docker-compose run --user $(id -u):$(id -g) api
   ```

---

## Security

### Best Practices

- Never commit AWS credentials to version control
- Use strong, randomly generated API keys
- Implement proper network security (firewalls, VPNs)
- Regularly update container images
- Monitor logs for suspicious activity
- Use HTTPS in production with proper certificates
