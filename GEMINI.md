# Project Context: Datapus - Containerized File Upload Service

## Project Overview

Datapus is a production-ready, containerized Node.js/Express API designed for secure and efficient file uploads to AWS S3. It integrates robust features such as API key authentication, comprehensive file validation (type, size, name), and ClamAV-based virus scanning. The service supports various upload methods, including single file uploads, URL-based uploads, and batch processing for multiple files. Files are organized hierarchically within S3, and the service includes enhanced security measures like rate limiting, CORS, and Helmet for HTTP security headers. It is built for easy deployment using Docker and is highly configurable via environment variables.

## Building and Running

This project is primarily designed for Dockerized deployment. For local development, Node.js and npm are required.

### Docker (Recommended)

To build and run the entire service (API and ClamAV):

```bash
docker-compose up -d --build
```

To view logs:

```bash
docker-compose logs -f api
```

To stop services:

```bash
docker-compose down
```

### Local Development

To install Node.js dependencies:

```bash
npm install
```

To start the application (ensure ClamAV is running separately or disable virus scanning by setting `ENABLE_VIRUS_SCAN=false` in `.env`):

```bash
npm start
```

For development with auto-reload:

```bash
npm run dev
```

## Development Conventions

- **API Authentication:** All API endpoints, except `/health`, require an API key in the `X-API-Key` header for authentication.
- **Configuration:** The application is configured entirely via environment variables, defined in the `.env` file. A `.env.example` is provided as a template.
- **Logging:** Structured logging is implemented using Winston, found in `src/utils/logger.js`.
- **Error Handling:** Centralized error handling is managed by `src/middleware/errorHandler.js`.
- **File Uploads:** The service supports `multipart/form-data` for direct file uploads and `application/json` for URL-based uploads.
- **Security:** Helmet, CORS, and `express-rate-limit` are used to enhance API security.
- **Request IDs:** Each request is assigned a unique `X-Request-ID` for traceability, included in logs.
