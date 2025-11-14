# Build this complete file API system following every step in this blueprint. Generate all code files.

You are tasked with building a production-ready, containerized Node.js/Express backend file API named "Datapus". Follow these instructions precisely to create a complete, working system.

---

## PROJECT OVERVIEW

Build a REST API service that:

- Receives file uploads via HTTP multipart requests
- Validates files (type, size, name, virus scan)
- Stores files in AWS S3 with organized folder structure
- Supports single and batch uploads with chunked processing
- Is fully containerized and deployable via Docker
- Configurable via environment variables

---

## STEP 1: PROJECT INITIALIZATION

### 1.1 Create Project Structure

Create the following directory structure exactly:

```
datapus/
├── src/
│   ├── index.js
│   ├── config/
│   │   └── config.js
│   ├── middleware/
│   │   ├── auth.js
│   │   ├── errorHandler.js
│   │   └── validation.js
│   ├── services/
│   │   ├── s3Service.js
│   │   ├── virusScanner.js
│   │   ├── fileValidator.js
│   │   └── apiKeyManager.js
│   ├── routes/
│   │   ├── upload.js
│   │   └── health.js
│   └── utils/
│       ├── logger.js
│       ├── errors.js
│       └── sizeParser.js
├── data/
│   └── .gitkeep
├── Dockerfile
├── docker-compose.yml
├── .dockerignore
├── .gitignore
├── .env.example
├── package.json
└── README.md
```

### 1.2 Initialize package.json

Create `package.json` with these exact dependencies:

```json
{
  "name": "datapus",
  "version": "1.0.0",
  "description": "Containerized file upload API with S3 storage",
  "main": "src/index.js",
  "scripts": {
    "start": "node src/index.js",
    "dev": "nodemon src/index.js"
  },
  "keywords": ["file-upload", "s3", "docker", "api"],
  "author": "",
  "license": "MIT",
  "dependencies": {
    "@aws-sdk/client-s3": "^3.621.0",
    "@aws-sdk/lib-storage": "^3.621.0",
    "express": "^4.19.2",
    "multer": "^1.4.5-lts.1",
    "helmet": "^7.1.0",
    "cors": "^2.8.5",
    "dotenv": "^16.4.5",
    "winston": "^3.13.0",
    "winston-daily-rotate-file": "^5.0.0",
    "clamscan": "^2.3.1",
    "uuid": "^10.0.0",
    "express-rate-limit": "^7.3.1"
  },
  "devDependencies": {
    "nodemon": "^3.1.4"
  },
  "engines": {
    "node": ">=20.0.0"
  }
}
```

---

## STEP 2: UTILITY MODULES

### 2.1 Size Parser (`src/utils/sizeParser.js`)

Create a utility to parse human-readable file sizes to bytes:

**Requirements:**

- Parse formats: "100MB", "1.5GB", "500KB", "10B"
- Support decimal values (e.g., "2.5GB")
- Case-insensitive (MB, mb, Mb all work)
- Throw descriptive errors for invalid formats
- Export function: `parseSize(sizeString)`

**Implementation logic:**

```javascript
// Extract number and unit using regex
// Units: B (bytes), KB (kilobytes), MB (megabytes), GB (gigabytes), TB (terabytes)
// Multipliers: B=1, KB=1024, MB=1024^2, GB=1024^3, TB=1024^4
// Return integer bytes
// Examples:
//   parseSize("100MB") => 104857600
//   parseSize("1.5GB") => 1610612736
//   parseSize("500KB") => 512000
```

### 2.2 Custom Errors (`src/utils/errors.js`)

Create custom error classes for consistent error handling:

**Required Error Classes:**

1. `ApiError` (base class)

   - Properties: statusCode, code, message, details
   - Constructor: (statusCode, code, message, details = {})

2. Specific error classes extending ApiError:

   - `AuthenticationError` - 401, "AUTHENTICATION_FAILED"
   - `ValidationError` - 400, custom code passed in
   - `NotFoundError` - 404, "NOT_FOUND"
   - `S3Error` - 500, "S3_OPERATION_FAILED"
   - `VirusScanError` - 420, "VIRUS_DETECTED"
   - `InternalError` - 500, "INTERNAL_ERROR"

### 2.3 Logger (`src/utils/logger.js`)

Create Winston logger with daily rotation and custom log levels:

```javascript
const winston = require("winston");
const DailyRotateFile = require("winston-daily-rotate-file");

// Define custom log levels to include 'http'
const levels = {
  error: 0,
  warn: 1,
  info: 2,
  http: 3, // Added http level as requested
  debug: 4,
};

// Create logger instance with custom levels
const logger = winston.createLogger({
  levels,
  level: process.env.LOG_LEVEL || "http", // Default to 'http' level
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.splat(),
    winston.format.json()
  ),
  defaultMeta: { service: "file-api" },
  transports: [
    // - Write all logs with importance level of info and above to combined-%DATE%.log
    new DailyRotateFile({
      level: "info",
      filename: "logs/combined-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      zippedArchive: true,
      maxSize: "20m",
      maxFiles: "14d",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
    }),
    // - Write all logs with importance level of error and above to error-%DATE%.log
    new DailyRotateFile({
      level: "error",
      filename: "logs/error-%DATE%.log",
      datePattern: "YYYY-MM-DD",
      zippedArchive: true,
      maxSize: "20m",
      maxFiles: "14d",
      format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
      ),
    }),
  ],
});

// If we're not in production, also log to the console with color formatting
if (process.env.NODE_ENV !== "production") {
  logger.add(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    })
  );
}

// Add a helper method to log with request ID if available
logger.addRequestId = (requestId) => {
  return winston.format((info) => {
    if (requestId) {
      info.requestId = requestId;
    }
    return info;
  })();
};

module.exports = logger;
```

---

## STEP 3: CONFIGURATION MANAGEMENT

### 3.1 Configuration Loader (`src/config/config.js`)

Load and validate all environment variables:

```javascript
const { parseSize } = require("../utils/sizeParser");

// Load environment variables
require("dotenv").config();

const config = {
  // Server
  port: process.env.PORT || 3000,
  nodeEnv: process.env.NODE_ENV || "development",

  // API Key
  apiKey: process.env.API_KEY || null, // Generated if null

  // AWS S3
  aws: {
    region: process.env.AWS_REGION || "us-east-1",
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    bucketName: process.env.S3_BUCKET_NAME,
    endpoint: process.env.S3_ENDPOINT || null,
  },

  // File Validation
  allowedFileTypes: (
    process.env.ALLOWED_FILE_TYPES || "pdf,jpg,jpeg,png,doc,docx,txt,zip"
  ).split(","),
  maxFileSize: parseSize(process.env.MAX_FILE_SIZE || "100MB"),
  maxRequestSize: parseSize(process.env.MAX_REQUEST_SIZE || "500MB"),

  // Virus Scanning
  virusScan: {
    enabled: process.env.ENABLE_VIRUS_SCAN === "true",
    host: process.env.CLAMAV_HOST || "clamav",
    port: parseInt(process.env.CLAMAV_PORT || "3310", 10),
  },

  // Upload Settings
  versioning: process.env.ENABLE_VERSIONING !== "false",
  chunkSize: parseSize(process.env.MULTIPART_CHUNK_SIZE || "5MB"),
  maxConcurrentUploads: parseInt(process.env.MAX_CONCURRENT_UPLOADS || "5", 10),

  // Folder Structure
  defaultSourceFolder: process.env.DEFAULT_SOURCE_FOLDER || "uploads",
  tagSeparator: process.env.TAG_SEPARATOR || "_",
};

// Validation
if (!config.aws.accessKeyId) {
  throw new Error("AWS_ACCESS_KEY_ID environment variable is required");
}

if (!config.aws.secretAccessKey) {
  throw new Error("AWS_SECRET_ACCESS_KEY environment variable is required");
}

if (!config.aws.bucketName) {
  throw new Error("S3_BUCKET_NAME environment variable is required");
}

// Log loaded configuration (masking secrets)
console.log("Configuration loaded:", {
  port: config.port,
  nodeEnv: config.nodeEnv,
  aws: {
    region: config.aws.region,
    bucketName: config.aws.bucketName,
    endpoint: config.aws.endpoint,
  },
  allowedFileTypes: config.allowedFileTypes,
  maxFileSize: config.maxFileSize,
  maxRequestSize: config.maxRequestSize,
  virusScan: config.virusScan,
  versioning: config.versioning,
});

module.exports = config;
```

**Validation:**

- Throw error if required AWS credentials missing
- Throw error if S3_BUCKET_NAME not provided
- Validate size parsing errors and provide clear messages
- Log loaded configuration (mask secrets)

**Export:** Configuration object

---

## STEP 4: SERVICES

### 4.1 API Key Manager (`src/services/apiKeyManager.js`)

Manage API key generation and validation:

```javascript
const crypto = require("crypto");
const fs = require("fs").promises;
const path = require("path");

/**
 * Generate a cryptographically secure random API key
 * @returns {string} Hex-encoded API key (64 characters)
 */
function generateApiKey() {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Validate an API key against the stored key using timing-safe comparison
 * @param {string} providedKey - The key to validate
 * @returns {Promise<boolean>} True if valid, false otherwise
 */
async function validateApiKey(providedKey) {
  if (!providedKey) {
    return false;
  }

  const apiKeyPath = path.join(__dirname, "../../data/api-key.txt");

  try {
    const storedKey = await fs.readFile(apiKeyPath, "utf8");
    const trimmedStoredKey = storedKey.trim();

    if (trimmedStoredKey.length !== providedKey.length) {
      return false;
    }

    // Use timing-safe comparison to prevent timing attacks
    const bufferA = Buffer.from(trimmedStoredKey, "utf8");
    const bufferB = Buffer.from(providedKey, "utf8");

    return crypto.timingSafeEqual(bufferA, bufferB);
  } catch (error) {
    console.error("Error validating API key:", error.message);
    return false;
  }
}

module.exports = {
  generateApiKey,
  validateApiKey,
};
```

### 4.2 File Validator (`src/services/fileValidator.js`)

Validate files before processing:

```javascript
const { ValidationError } = require("../utils/errors");

/**
 * Validate and sanitize a filename
 * @param {string} filename - Original filename
 * @returns {string} Sanitized filename
 * @throws {ValidationError} If filename is invalid
 */
function validateFileName(filename) {
  if (!filename || typeof filename !== "string") {
    throw new ValidationError(
      "INVALID_FILENAME",
      "Filename must be a non-empty string"
    );
  }

  // Check max length
  if (filename.length > 255) {
    throw new ValidationError(
      "INVALID_FILENAME",
      "Filename exceeds maximum length of 255 characters"
    );
  }

  // Define invalid characters
  const invalidChars = /[<>:"/\\|?*\0\n\r\t]/g;

  // Sanitize filename by removing invalid characters
  let sanitized = filename.replace(invalidChars, "_");

  // Check for path traversal attempts
  if (sanitized.includes("..") || sanitized.startsWith("/")) {
    throw new ValidationError(
      "INVALID_FILENAME",
      "Filename contains path traversal characters"
    );
  }

  // Ensure filename is not empty after sanitization
  if (!sanitized.trim()) {
    throw new ValidationError(
      "INVALID_FILENAME",
      "Filename is empty after sanitization"
    );
  }

  return sanitized;
}

/**
 * Validate and sanitize a filename, ensuring uniqueness by adding a suffix if needed
 * @param {string} filename - Original filename
 * @param {function} existsCheck - Function to check if a filename already exists
 * @returns {string} Unique sanitized filename
 * @throws {ValidationError} If filename is invalid
 */
async function validateAndEnsureUniqueFilename(filename, existsCheck) {
  let sanitized = validateFileName(filename);

  // If an existsCheck function is provided, ensure uniqueness
  if (existsCheck && typeof existsCheck === "function") {
    let uniqueSanitized = sanitized;
    let counter = 1;

    // Check if the sanitized filename already exists
    while (await existsCheck(uniqueSanitized)) {
      // Extract file extension and name
      const lastDotIndex = sanitized.lastIndexOf(".");
      let namePart, extPart;

      if (lastDotIndex === -1) {
        // No extension
        namePart = sanitized;
        extPart = "";
      } else {
        namePart = sanitized.substring(0, lastDotIndex);
        extPart = sanitized.substring(lastDotIndex);
      }

      // Add counter to make it unique
      uniqueSanitized = `${namePart}_${counter}${extPart}`;
      counter++;

      // Prevent infinite loops
      if (counter > 999999) {
        // Arbitrary large number to prevent infinite loops
        throw new ValidationError(
          "INVALID_FILENAME",
          "Unable to generate unique filename after multiple attempts"
        );
      }
    }

    sanitized = uniqueSanitized;
  }

  return sanitized;
}

/**
 * Validate file type based on extension and mimetype
 * @param {string} filename - Filename to validate
 * @param {string} mimetype - MIME type of the file
 * @param {string[]} allowedTypes - Array of allowed file extensions
 * @returns {boolean} True if file type is valid
 * @throws {ValidationError} If file type is not allowed
 */
function validateFileType(filename, mimetype, allowedTypes) {
  if (!filename) {
    throw new ValidationError("INVALID_FILE_TYPE", "Filename is required");
  }

  if (!Array.isArray(allowedTypes) || allowedTypes.length === 0) {
    throw new ValidationError(
      "INVALID_FILE_TYPE",
      "Allowed file types must be a non-empty array"
    );
  }

  // Extract extension from filename
  const ext = filename.split(".").pop().toLowerCase();

  // Check if extension is in allowed types
  if (!allowedTypes.includes(ext)) {
    throw new ValidationError(
      "INVALID_FILE_TYPE",
      `File type ".${ext}" is not allowed. Allowed types: ${allowedTypes.join(
        ", "
      )}`
    );
  }

  return true;
}

/**
 * Validate file size
 * @param {number} size - Size of the file in bytes
 * @param {number} maxSize - Maximum allowed size in bytes
 * @returns {boolean} True if file size is valid
 * @throws {ValidationError} If file size exceeds the limit
 */
function validateFileSize(size, maxSize) {
  if (typeof size !== "number" || typeof maxSize !== "number") {
    throw new ValidationError(
      "INVALID_FILE_SIZE",
      "Size parameters must be numbers"
    );
  }

  if (size > maxSize) {
    throw new ValidationError(
      "FILE_TOO_LARGE",
      `File size ${size} bytes exceeds maximum allowed size of ${maxSize} bytes (${(
        maxSize /
        1024 /
        1024
      ).toFixed(2)}MB)`,
      { fileSize: size, maxSize }
    );
  }

  return true;
}

/**
 * Validate the total size of multiple files in a batch
 * @param {Array} files - Array of file objects
 * @param {number} maxRequestSize - Maximum allowed total size in bytes
 * @returns {boolean} True if batch size is valid
 * @throws {ValidationError} If total size exceeds the limit
 */
function validateBatchSize(files, maxRequestSize) {
  if (!Array.isArray(files)) {
    throw new ValidationError("INVALID_BATCH_SIZE", "Files must be an array");
  }

  const totalSize = files.reduce((sum, file) => sum + (file.size || 0), 0);

  if (totalSize > maxRequestSize) {
    throw new ValidationError(
      "REQUEST_TOO_LARGE",
      `Total request size ${totalSize} bytes exceeds maximum allowed size of ${maxRequestSize} bytes (${(
        maxRequestSize /
        1024 /
        1024
      ).toFixed(2)}MB)`,
      { totalSize, maxRequestSize }
    );
  }

  return true;
}

module.exports = {
  validateFileName,
  validateAndEnsureUniqueFilename,
  validateFileType,
  validateFileSize,
  validateBatchSize,
};
```

### 4.3 Virus Scanner (`src/services/virusScanner.js`)

Integrate with ClamAV for virus scanning:

```javascript
const NodeClam = require("clamscan");
const fs = require("fs").promises;
const { tmpdir } = require("os");
const { join } = require("path");
const { VirusScanError } = require("../utils/errors");

let clamScanner = null;

/**
 * Initialize the ClamAV scanner
 * @param {Object} config - Application configuration
 * @returns {Promise<Object|null>} Initialized scanner or null if disabled
 */
async function initializeScanner(config) {
  if (!config.virusScan.enabled) {
    return null;
  }

  try {
    clamScanner = await new NodeClam().init({
      clamdscan: {
        host: config.virusScan.host,
        port: config.virusScan.port,
        timeout: 60000,
      },
      preference: "clamdscan",
    });

    return clamScanner;
  } catch (error) {
    console.error("Failed to initialize ClamAV scanner:", error.message);
    throw new Error(`ClamAV initialization failed: ${error.message}`);
  }
}

/**
 * Scan a file for viruses
 * @param {string} filePath - Path to the file to scan
 * @returns {Promise<Object>} Scan results { isInfected: boolean, viruses: array }
 */
async function scanFile(filePath) {
  if (!clamScanner) {
    return { isInfected: false };
  }

  try {
    const { isInfected, viruses } = await clamScanner.scan_file(filePath);

    console.log(
      `Virus scan completed for ${filePath}: infected=${isInfected}`,
      { viruses }
    );

    if (isInfected && viruses && viruses.length > 0) {
      throw new VirusScanError(`Virus detected: ${viruses.join(", ")}`);
    }

    return { isInfected, viruses: viruses || [] };
  } catch (error) {
    console.error(`Virus scan failed for file ${filePath}:`, error.message);
    throw error;
  }
}

/**
 * Scan a buffer for viruses by writing to a temporary file
 * @param {Buffer} buffer - Buffer to scan
 * @returns {Promise<Object>} Scan results { isInfected: boolean, viruses: array }
 */
async function scanBuffer(buffer) {
  if (!clamScanner) {
    return { isInfected: false };
  }

  let tempFilePath;

  try {
    // Create a temporary file
    const tempFileName = `temp_scan_${Date.now()}_${Math.random()
      .toString(36)
      .substring(2, 15)}`;
    tempFilePath = join(tmpdir(), tempFileName);

    // Write buffer to temp file
    await fs.writeFile(tempFilePath, buffer);

    // Scan the temp file
    const result = await scanFile(tempFilePath);

    return result;
  } catch (error) {
    console.error("Buffer scan failed:", error.message);
    throw error;
  } finally {
    // Clean up temp file if it was created
    if (tempFilePath) {
      try {
        await fs.unlink(tempFilePath);
      } catch (unlinkError) {
        console.warn(
          `Failed to delete temporary file ${tempFilePath}:`,
          unlinkError.message
        );
      }
    }
  }
}

module.exports = {
  initializeScanner,
  scanFile,
  scanBuffer,
};
```

### 4.4 S3 Service (`src/services/s3Service.js`)

Handle all S3 operations:

```javascript
const { S3Client } = require("@aws-sdk/client-s3");
const { Upload } = require("@aws-sdk/lib-storage");
const { S3Error } = require("../utils/errors");
const config = require("../config/config");

const s3Client = new S3Client({
  region: config.aws.region,
  credentials: {
    accessKeyId: config.aws.accessKeyId,
    secretAccessKey: config.aws.secretAccessKey,
  },
  endpoint: config.aws.endpoint || undefined,
});

/**
 * Generate S3 key with organized folder structure
 * @param {string} source - Source folder name
 * @param {string} tag - Tag subfolder name
 * @param {string} filename - Original filename
 * @returns {string} S3 key in format {source}/{tag}/{timestamp}_{filename}
 */
function generateS3Key(source, tag, filename) {
  // Sanitize source and tag (remove special characters)
  const sanitizedSource = source.replace(/[^a-zA-Z0-9-_]/g, "");
  const sanitizedTag = tag.replace(/[^a-zA-Z0-9-_]/g, "");

  // Generate timestamp in YYYY-MM-DDTHH-mm-ss format (avoiding colons for S3 compatibility)
  const timestamp = new Date()
    .toISOString()
    .replace(/\.\d{3}Z$/, "") // Remove milliseconds and Z
    .replace(/:/g, "-"); // Replace colons with hyphens for S3 compatibility

  // Create the S3 key
  const s3Key = `${sanitizedSource}/${sanitizedTag}/${timestamp}_${filename}`;

  return s3Key;
}

/**
 * Upload a file to S3
 * @param {Buffer|ReadableStream} fileStream - File content to upload
 * @param {string} s3Key - S3 object key
 * @param {Object} metadata - File metadata
 * @param {Object} tags - Tags to apply to the object
 * @returns {Promise<Object>} Upload result with location, versionId, and etag
 */
async function uploadFile(fileStream, s3Key, metadata, tags) {
  try {
    // Convert buffer to readable stream if needed
    const body = Buffer.isBuffer(fileStream)
      ? require("stream").Readable.from(fileStream)
      : fileStream;

    const upload = new Upload({
      client: s3Client,
      params: {
        Bucket: config.aws.bucketName,
        Key: s3Key,
        Body: body,
        ContentType: metadata.contentType,
        Metadata: {
          "original-filename": metadata.originalFilename,
          "upload-timestamp": new Date().toISOString(),
          "source-ip": metadata.sourceIp,
          "content-type": metadata.contentType,
          "file-size": metadata.size.toString(),
        },
        Tagging: formatTags(tags),
      },
      queueSize: 4,
      partSize: config.chunkSize,
    });

    const result = await upload.done();

    return {
      location: result.Location,
      versionId: result.VersionId || null, // VersionId will be null if S3 versioning is not enabled
      etag: result.ETag,
    };
  } catch (error) {
    console.error("S3 upload failed:", error.message);
    throw new S3Error(`Failed to upload file to S3: ${error.message}`);
  }
}

/**
 * Format tags object to S3 tag string
 * @param {Object} tagsObject - Tags object
 * @returns {string} Formatted tags string for S3
 */
function formatTags(tagsObject) {
  const tags = Object.entries(tagsObject)
    .map(
      ([key, value]) =>
        `${encodeURIComponent(key)}=${encodeURIComponent(value)}`
    )
    .join("&");
  return tags;
}

/**
 * Test S3 connection
 * @returns {Promise<boolean>} True if connection is successful
 */
async function testConnection() {
  try {
    // HeadBucket operation to test connection
    const { HeadBucketCommand } = require("@aws-sdk/client-s3");
    const command = new HeadBucketCommand({ Bucket: config.aws.bucketName });
    await s3Client.send(command);
    return true;
  } catch (error) {
    console.error("S3 connection test failed:", error.message);
    return false;
  }
}

module.exports = {
  generateS3Key,
  uploadFile,
  formatTags,
  testConnection,
};
```

---

## STEP 5: MIDDLEWARE

### 5.1 Authentication Middleware (`src/middleware/auth.js`)

Verify API key in requests:

```javascript
const apiKeyManager = require("../services/apiKeyManager");
const { AuthenticationError } = require("../utils/errors");

/**
 * Middleware to authenticate requests using API key
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
async function authenticate(req, res, next) {
  const apiKey = req.headers["x-api-key"];

  if (!apiKey) {
    return next(new AuthenticationError("Missing API key"));
  }

  const isValid = await apiKeyManager.validateApiKey(apiKey);

  if (!isValid) {
    return next(new AuthenticationError("Invalid API key"));
  }

  next();
}

module.exports = { authenticate };
```

### 5.2 Validation Middleware (`src/middleware/validation.js`)

Express middleware for request validation:

```javascript
const multer = require("multer");
const config = require("../config/config");
const { fileValidator } = require("../services/fileValidator");
const { ValidationError } = require("../utils/errors");

/**
 * Configure multer for file uploads
 * @returns {Object} Configured multer middleware
 */
function setupMulter() {
  // Memory storage (files are kept in memory as buffers)
  const storage = multer.memoryStorage();

  // File filter to check file type before accepting
  const fileFilter = (req, file, cb) => {
    try {
      // First validate file extension
      fileValidator.validateFileType(
        file.originalname,
        file.mimetype,
        config.allowedFileTypes
      );

      // For better security, use magic number detection to verify file type
      // Check first few bytes of the file buffer to confirm it matches the expected type
      if (file.buffer && file.buffer.length > 0) {
        const allowedTypes = config.allowedFileTypes;
        const fileExtension = file.originalname.split(".").pop().toLowerCase();

        // This is a simplified check - in production, consider using the 'file-type' package
        // for proper magic number validation
        const isValidType = validateFileTypeByMagicNumber(
          file.buffer,
          fileExtension
        );
        if (!isValidType) {
          throw new ValidationError(
            "INVALID_FILE_TYPE",
            `File type does not match the actual file content: ${fileExtension}`
          );
        }
      }

      // If validation passes, accept the file
      cb(null, true);
    } catch (error) {
      // If validation fails, reject the file with error
      cb(null, false);
      req.fileValidationError = error.message; // Store error for later handling
    }
  };

  return multer({
    storage,
    fileFilter,
    limits: {
      fileSize: config.maxFileSize,
      files: 10, // max files in batch
    },
  });
}

/**
 * Validate file type based on magic number detection (simplified implementation)
 * In production, use the 'file-type' package for reliable detection
 * @param {Buffer} buffer - File buffer to analyze
 * @param {string} expectedExtension - Expected file extension
 * @returns {boolean} True if file type matches expected type
 */
function validateFileTypeByMagicNumber(buffer, expectedExtension) {
  if (!buffer || buffer.length < 4) {
    // If buffer is too small, fallback to extension validation
    return true;
  }

  // Read the first few bytes to identify the file type
  const header = buffer.slice(0, 4);
  const hexHeader = header.toString("hex").toLowerCase();

  // Define magic numbers for common file types
  const magicNumbers = {
    jpg: ["ffd8ffe0", "ffd8ffe1", "ffd8ffe2", "ffd8ffe3", "ffd8ffe8"],
    jpeg: ["ffd8ffe0", "ffd8ffe1", "ffd8ffe2", "ffd8ffe3", "ffd8ffe8"],
    png: ["89504e47"],
    gif: ["47494638"],
    pdf: ["25504446"],
    zip: ["504b0304", "504b0506", "504b0708"],
    doc: ["d0cf11e0"],
    docx: ["504b0304"],
    xls: ["d0cf11e0"],
    xlsx: ["504b0304"],
    txt: ["74657374"], // Only as fallback, many plain text files don't have specific magic numbers
  };

  const expectedMagicNumbers = magicNumbers[expectedExtension];
  if (!expectedMagicNumbers) {
    // If we don't have magic number for this type, fall back to extension validation
    return true;
  }

  // Check if the file's header matches any of the expected magic numbers
  return expectedMagicNumbers.some((magic) => hexHeader.startsWith(magic));
}

/**
 * Validate upload request
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
function validateUploadRequest(req, res, next) {
  // Check if file exists in req.file or req.files
  const files = req.files || req.file;
  if (!files) {
    if (req.fileValidationError) {
      // Handle file validation errors from multer
      return next(
        new ValidationError("INVALID_FILE_TYPE", req.fileValidationError)
      );
    }
    return next(
      new ValidationError("MISSING_FILE", "No file provided in request")
    );
  }

  const filesArray = Array.isArray(files) ? files : [files];

  try {
    // Validate each file
    for (const file of filesArray) {
      // Validate filename
      const sanitizedFilename = fileValidator.validateFileName(
        file.originalname
      );
      file.originalname = sanitizedFilename; // Update with sanitized name

      // Validate file type
      fileValidator.validateFileType(
        file.originalname,
        file.mimetype,
        config.allowedFileTypes
      );

      // Validate file size
      fileValidator.validateFileSize(file.size, config.maxFileSize);
    }

    // Validate total batch size if multiple files
    if (filesArray.length > 1) {
      fileValidator.validateBatchSize(filesArray, config.maxRequestSize);
    }

    // Validate request fields (source, tag)
    const { source = config.defaultSourceFolder, tag = "general" } = req.body;

    // Basic validation for source and tag
    if (typeof source !== "string" || source.trim().length === 0) {
      return next(
        new ValidationError(
          "INVALID_SOURCE",
          "Source must be a non-empty string"
        )
      );
    }

    if (typeof tag !== "string" || tag.trim().length === 0) {
      return next(
        new ValidationError("INVALID_TAG", "Tag must be a non-empty string")
      );
    }

    // Attach validated data to req.validated
    req.validated = {
      source: source.trim(),
      tag: tag.trim(),
    };

    next();
  } catch (error) {
    next(error);
  }
}

module.exports = {
  setupMulter,
  validateUploadRequest,
};
```

### 5.3 Error Handler (`src/middleware/errorHandler.js`)

Global error handling middleware:

```javascript
const { v4: uuid } = require("uuid");
const logger = require("../utils/logger");
const { ApiError } = require("../utils/errors");

/**
 * Global error handling middleware
 * @param {Error} err - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
function errorHandler(err, req, res, next) {
  const requestId = req.id || uuid();

  // Log error with full stack trace
  logger.error("Request error", {
    requestId,
    error: err.message,
    stack: err.stack,
    code: err.code,
    details: err.details,
  });

  // Handle known error types
  if (err instanceof ApiError) {
    return res.status(err.statusCode).json({
      success: false,
      error: {
        code: err.code,
        message: err.message,
        details: err.details,
        timestamp: new Date().toISOString(),
        requestId,
      },
    });
  }

  // Handle multer errors
  if (err.name === "MulterError") {
    let errorCode, errorMessage;

    switch (err.code) {
      case "LIMIT_FILE_SIZE":
        errorCode = "FILE_TOO_LARGE";
        errorMessage = "File size exceeds the maximum allowed size";
        break;
      case "LIMIT_FILE_COUNT":
        errorCode = "TOO_MANY_FILES";
        errorMessage = "Too many files provided";
        break;
      case "LIMIT_UNEXPECTED_FILE":
        errorCode = "UNEXPECTED_FILE";
        errorMessage = "Unexpected field name in form";
        break;
      default:
        errorCode = "UPLOAD_ERROR";
        errorMessage = err.message || "An error occurred during file upload";
    }

    return res.status(400).json({
      success: false,
      error: {
        code: errorCode,
        message: errorMessage,
        timestamp: new Date().toISOString(),
        requestId,
      },
    });
  }

  // Handle unexpected errors
  return res.status(500).json({
    success: false,
    error: {
      code: "INTERNAL_ERROR",
      message: "An unexpected error occurred",
      timestamp: new Date().toISOString(),
      requestId,
    },
  });
}

module.exports = { errorHandler };
```

**Export:** errorHandler middleware

---

## STEP 6: ROUTES

### 6.1 Upload Routes (`src/routes/upload.js`)

Define upload endpoints:

**POST `/api/v1/upload` - Single File Upload**

Flow:

1. Apply authentication middleware
2. Apply multer single file middleware
3. Apply validation middleware
4. Process request:

   ```javascript
   async (req, res, next) => {  try {    const file = req.file;    const { source, tag } = req.body;        // Validate filename    const sanitizedName = fileValidator.validateFileName(file.originalname);        // Validate file type    fileValidator.validateFileType(      sanitizedName,      file.mimetype,      config.allowedFileTypes    );        // Validate size    fileValidator.validateFileSize(file.size, config.maxFileSize);        // Scan for viruses if enabled    if (config.virusScan.enabled) {      const scanResult = await virusScanner.scanBuffer(file.buffer);      if (scanResult.isInfected) {        throw new VirusScanError(          `Virus detected: ${scanResult.viruses.join(', ')}`        );      }    }        // Generate S3 key    const s3Key = s3Service.generateS3Key(      source || config.defaultSourceFolder,      tag || 'general',      sanitizedName    );        // Upload to S3    const uploadResult = await s3Service.uploadFile(      file.buffer,      s3Key,      {        contentType: file.mimetype,        originalFilename: file.originalname,        sourceIp: req.ip,        size: file.size      },      {        source: source || config.defaultSourceFolder,        tag: tag || 'general',        'upload-date': new Date().toISOString().split('T')[0],        'content-type': file.mimetype      }    );        // Log successful upload    logger.info('File uploaded successfully', {      filename: sanitizedName,      size: file.size,      s3Key,      source,      tag    });        // Return success response    res.json({      success: true,      data: {        uploadId: uuid(),        filename: sanitizedName,        originalFilename: file.originalname,        s3Location: `s3://${config.aws.bucketName}/${s3Key}`,        s3Key,        versionId: uploadResult.versionId,        size: file.size,        contentType: file.mimetype,        uploadedAt: new Date().toISOString(),        metadata: {          source: source || config.defaultSourceFolder,          tag: tag || 'general'        }      }    });  } catch (error) {    next(error);  }}
   ```

**POST `/api/v1/upload/batch` - Batch File Upload**

Flow:

1.  Apply authentication middleware
2.  Apply multer array middleware (max 10 files)
3.  Apply validation middleware
4.  Process request:
        ```javascript
        async (req, res, next) => {  try {    const files = req.files;    const { source, tag } = req.body;        // Validate total batch size    fileValidator.validateBatchSize(files, config.maxRequestSize);        // Process files concurrently (with limit)    const results = [];    const chunks = [];        // Split files into chunks based on maxConcurrentUploads    for (let i = 0; i < files.length; i += config.maxConcurrentUploads) {      chunks.push(files.slice(i, i + config.maxConcurrentUploads));    }        // Process each chunk    for (const chunk of chunks) {      const chunkResults = await Promise.allSettled(        chunk.map(file => processFile(file, source, tag))      );            // Map results      chunkResults.forEach((result, index) => {        if (result.status === 'fulfilled') {          results.push({            filename: chunk[index].originalname,            success: true,            data: result.value          });        } else {          results.push({            filename: chunk[index].originalname,            success: false,            error: {              code: result.reason.code || 'UPLOAD_FAILED',              message: result.reason.message            }          });        }      });    }        // Count successes and failures    const successful = results.filter(r => r.success).length;    const failed = results.filter(r => !r.success).length;        // Return batch results    res.json({      success: true,      data: {        total: files.length,        successful,        failed,        results      }    });  } catch (error) {    next(error);  }}// Helper function to process single file
    async function processFile(file, source, tag) {
    // Validate filename
    const sanitizedName = fileValidator.validateFileName(file.originalname);

// Validate file type
fileValidator.validateFileType(
sanitizedName,
file.mimetype,
config.allowedFileTypes
);

// Validate size
fileValidator.validateFileSize(file.size, config.maxFileSize);

// Scan for viruses if enabled
if (config.virusScan.enabled) {
const scanResult = await virusScanner.scanBuffer(file.buffer);
if (scanResult.isInfected) {
throw new VirusScanError(
`Virus detected: ${scanResult.viruses.join(', ')}`
);
}
}

// Generate S3 key
const s3Key = s3Service.generateS3Key(
source || config.defaultSourceFolder,
tag || 'general',
sanitizedName
);

// Convert buffer to readable stream for efficient upload
const bufferStream = require('stream').Readable.from(file.buffer);

// Upload to S3
const uploadResult = await s3Service.uploadFile(
bufferStream,
s3Key,
{
contentType: file.mimetype,
originalFilename: file.originalname,
sourceIp: null, // source IP not available in batch context
size: file.size
},
{
source: source || config.defaultSourceFolder,
tag: tag || 'general',
'upload-date': new Date().toISOString().split('T')[0],
'content-type': file.mimetype
}
);

return {
uploadId: uuid(),
filename: sanitizedName,
originalFilename: file.originalname,
s3Location: `s3://${config.aws.bucketName}/${s3Key}`,
s3Key,
versionId: uploadResult.versionId,
size: file.size,
contentType: file.mimetype,
uploadedAt: new Date().toISOString(),
metadata: {
source: source || config.defaultSourceFolder,
tag: tag || 'general'
}
};
}
```

**Export:** Express router with routes

### 6.2 Health Routes (`src/routes/health.js`)

Health check endpoint:

**GET `/health`**

```javascript
router.get("/health", async (req, res) => {
  const health = {
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    checks: {
      api: "ok",
      s3: "unknown",
      virusScanner: "unknown",
    },
  };

  // Test S3 connection
  try {
    const s3Connected = await s3Service.testConnection();
    health.checks.s3 = s3Connected ? "ok" : "error";
  } catch (error) {
    health.checks.s3 = "error";
    health.status = "degraded";
  }

  // Test ClamAV if enabled
  if (config.virusScan.enabled) {
    try {
      // Create a temporary test connection to ClamAV to verify it's running
      const NodeClam = require("clamscan");
      const testScanner = await new NodeClam().init({
        clamdscan: {
          host: config.virusScan.host,
          port: config.virusScan.port,
          timeout: 5000, // 5 second timeout for health check
        },
        preference: "clamdscan",
      });

      // Perform a ping/echo test
      await testScanner.ping(); // This should ping the ClamAV daemon

      health.checks.virusScanner = "ok";
    } catch (error) {
      console.error("ClamAV health check failed:", error.message);
      health.checks.virusScanner = "error";
      health.status = "degraded";
    }
  } else {
    health.checks.virusScanner = "disabled";
  }

  const statusCode = health.status === "ok" ? 200 : 503;
  res.status(statusCode).json(health);
});
```

**Export:** Express router

---

## STEP 7: MAIN APPLICATION

### 7.1 Application Entry Point (`src/index.js`)

Wire everything together:

```javascript
const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { v4: uuid } = require("uuid");

// Load config
require("dotenv").config();
const config = require("./config/config");
const logger = require("./utils/logger");

// Services
const apiKeyManager = require("./services/apiKeyManager");
const virusScanner = require("./services/virusScanner");

// Routes
const uploadRoutes = require("./routes/upload");
const healthRoutes = require("./routes/health");

// Middleware
const errorHandler = require("./middleware/errorHandler");

// Initialize app
const app = express();

// Trust proxy (important for rate limiting behind reverse proxy)
app.set("trust proxy", 1);

// Security middleware
app.use(helmet());
app.use(
  cors({
    origin: process.env.CORS_ORIGIN || "*",
    methods: ["GET", "POST"],
    allowedHeaders: ["Content-Type", "X-API-Key"],
  })
);

// Rate limiting
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // limit each IP to 100 requests per windowMs
  message: "Too many requests from this IP",
  standardHeaders: true,
  legacyHeaders: false,
});
app.use("/api/", limiter);

// Request ID middleware
app.use((req, res, next) => {
  req.id = uuid();
  res.setHeader("X-Request-ID", req.id);
  next();
});

// Logging middleware
app.use((req, res, next) => {
  logger.http("Incoming request", {
    requestId: req.id,
    method: req.method,
    path: req.path,
    ip: req.ip,
  });
  next();
});

// Body parser for JSON
app.use(express.json());

// Mount routes
app.use("/health", healthRoutes);
app.use("/api/v1", uploadRoutes);

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: {
      code: "NOT_FOUND",
      message: "Endpoint not found",
      path: req.path,
    },
  });
});

// Error handler (must be last)
app.use(errorHandler);

// Startup sequence
async function startup() {
  try {
    logger.info("Starting File API service...");

    // Load or generate API key
    const apiKey = await apiKeyManager.generateApiKey();
    logger.info("API Key loaded", {
      key: apiKey.substring(0, 8) + "...",
    });
    console.log("\n========================================");
    console.log("API KEY:", apiKey);
    console.log("========================================\n");

    // Initialize virus scanner
    if (config.virusScan.enabled) {
      await virusScanner.initializeScanner(config);
      logger.info("Virus scanner initialized");
    } else {
      logger.warn("Virus scanning is DISABLED");
    }

    // Start server
    const server = app.listen(config.port, () => {
      logger.info(`Server running on port ${config.port}`);
      logger.info(`Environment: ${config.nodeEnv}`);
      logger.info(`S3 Bucket: ${config.aws.bucketName}`);
    });

    // Graceful shutdown
    process.on("SIGTERM", () => {
      logger.info("SIGTERM received, shutting down gracefully");
      server.close(() => {
        logger.info("Server closed");
        process.exit(0);
      });
    });
  } catch (error) {
    logger.error("Failed to start service", { error: error.message });
    process.exit(1);
  }
}

// Start the application
startup();
```

---

## STEP 8: DOCKER CONFIGURATION

### 8.1 Dockerfile

Create multi-stage build:

```dockerfile
# Stage 1: Builder
FROM node:20-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --omit=dev

# Stage 2: Production
FROM node:20-alpine

# Create non-root user
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nodejs -u 1001

WORKDIR /app

# Copy dependencies from builder
COPY --from=builder /app/node_modules ./node_modules

# Copy application code
COPY --chown=nodejs:nodejs src ./src

# Create data directory for API key storage
RUN mkdir -p /app/data && chown nodejs:nodejs /app/data

# Create logs directory
RUN mkdir -p /app/logs && chown nodejs:nodejs /app/logs

# Switch to non-root user
USER nodejs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
  CMD node -e "require('http').get('http://localhost:3000/health', (r) => {process.exit(r.statusCode === 200 ? 0 : 1)})"

# Start application
CMD ["node", "src/index.js"]
```

### 8.2 docker-compose.yml

Complete orchestration:

```yaml
version: "3.8"

services:
  api:
    build:
      context: .
      dockerfile: Dockerfile
    container_name: datapus
    ports:
      - "${PORT:-3000}:3000"
    environment:
      # Server
      - NODE_ENV=${NODE_ENV:-production}
      - PORT=3000

      # API Key (will be auto-generated if not provided)
      - API_KEY=${API_KEY:-}

      # AWS S3
      - AWS_REGION=${AWS_REGION:-us-east-1}
      - AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
      - AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
      - S3_BUCKET_NAME=${S3_BUCKET_NAME}
      - S3_ENDPOINT=${S3_ENDPOINT:-}

      # File Validation
      - ALLOWED_FILE_TYPES=${ALLOWED_FILE_TYPES:-pdf,jpg,jpeg,png,doc,docx,txt,zip}
      - MAX_FILE_SIZE=${MAX_FILE_SIZE:-100MB}
      - MAX_REQUEST_SIZE=${MAX_REQUEST_SIZE:-500MB}

      # Virus Scanning
      - ENABLE_VIRUS_SCAN=${ENABLE_VIRUS_SCAN:-true}
      - CLAMAV_HOST=clamav
      - CLAMAV_PORT=3310

      # Upload Configuration
      - ENABLE_VERSIONING=${ENABLE_VERSIONING:-true}
      - MULTIPART_CHUNK_SIZE=${MULTIPART_CHUNK_SIZE:-5MB}
      - MAX_CONCURRENT_UPLOADS=${MAX_CONCURRENT_UPLOADS:-5}

      # Folder Structure
      - DEFAULT_SOURCE_FOLDER=${DEFAULT_SOURCE_FOLDER:-uploads}
      - TAG_SEPARATOR=${TAG_SEPARATOR:-_}
    volumes:
      - ./data:/app/data
      - ./logs:/app/logs
    depends_on:
      clamav:
        condition: service_healthy
    networks:
      - datapus-network
    restart: unless-stopped

  clamav:
    image: clamav/clamav:1.2.0
    container_name: clamav
    ports:
      - "3310:3310"
    volumes:
      - clamav-data:/var/lib/clamav
    healthcheck:
      test: ["CMD", "clamscan", "--ping"]
      interval: 60s
      timeout: 10s
      retries: 3
      start_period: 120s
    networks:
      - file-api-network
    restart: unless-stopped

volumes:
  clamav-data:
    driver: local

networks:
  file-api-network:
    driver: bridge
```

### 8.3 .dockerignore

Exclude unnecessary files from Docker build:

```
node_modules
npm-debug.log
.env
.env.*
.git
.gitignore
logs
*.log
data/*.txt
.DS_Store
coverage
.vscode
.idea
```

### 8.4 .gitignore

Exclude sensitive and generated files:

```
# Dependencies
node_modules/

# Environment variables
.env
.env.local
.env.production

# Logs
logs/
*.log
npm-debug.log*

# API Keys
data/api-key.txt

# OS
.DS_Store
Thumbs.db

# IDEs
.vscode/
.idea/
*.swp
*.swo

# Docker
docker-compose.override.yml

# Testing
coverage/
.nyc_output/
```

---

## STEP 9: ENVIRONMENT CONFIGURATION

### 9.1 .env.example

Complete environment variable template:

```bash
# ===========================================
# FILE API CONFIGURATION
# ===========================================

# ------------------------------------------
# Server Configuration
# ------------------------------------------
PORT=3000
NODE_ENV=production

# API Key - Leave empty to auto-generate on first run
# Once generated, it will be saved to ./data/api-key.txt
API_KEY=

# CORS Configuration (optional)
# CORS_ORIGIN=https://yourdomain.com

# ------------------------------------------
# AWS S3 Configuration
# ------------------------------------------
# REQUIRED: AWS credentials and bucket name
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=your_access_key_here
AWS_SECRET_ACCESS_KEY=your_secret_key_here
S3_BUCKET_NAME=your-bucket-name

# Optional: For S3-compatible storage (MinIO, DigitalOcean Spaces, etc.)
# S3_ENDPOINT=https://nyc3.digitaloceanspaces.com

# ------------------------------------------
# File Validation
# ------------------------------------------
# Comma-separated list of allowed file extensions (no dots, lowercase)
ALLOWED_FILE_TYPES=pdf,jpg,jpeg,png,gif,doc,docx,xls,xlsx,txt,zip,mp4,mov

# Maximum file size per file (supports: KB, MB, GB)
# Examples: 50MB, 1.5GB, 500KB
MAX_FILE_SIZE=100MB

# Maximum total request size for batch uploads
MAX_REQUEST_SIZE=500MB

# ------------------------------------------
# Virus Scanning
# ------------------------------------------
# Enable/disable virus scanning (true/false)
ENABLE_VIRUS_SCAN=true

# ClamAV connection settings (use service name from docker-compose)
CLAMAV_HOST=clamav
CLAMAV_PORT=3310

# ------------------------------------------
# Upload Configuration
# ------------------------------------------
# Enable S3 versioning (true/false)
ENABLE_VERSIONING=true

# Chunk size for multipart uploads
MULTIPART_CHUNK_SIZE=5MB

# Maximum number of concurrent file uploads in batch operations
MAX_CONCURRENT_UPLOADS=5

# ------------------------------------------
# S3 Folder Structure
# ------------------------------------------
# Default folder name if 'source' not provided in request
DEFAULT_SOURCE_FOLDER=uploads

# Separator character for tags in folder structure
TAG_SEPARATOR=_
```

---

## STEP 10: COMPREHENSIVE DOCUMENTATION

### 10.1 README.md

Create complete documentation:

````markdown
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
````

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
  -H "X-API-Key: your-api-key-here" \
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

**Success Response (200):**

```json
{
  "success": true,
  "data": {
    "uploadId": "a3f2b8c4-d1e9-f0a7-b3c5-d8e2f4a1b6c9",
    "filename": "document.pdf",
    "originalFilename": "My Document.pdf",
    "s3Location": "s3://my-bucket/client-portal/contracts/2025-11-14T10-30-00_document.pdf",
    "s3Key": "client-portal/contracts/2025-11-14T10-30-00_document.pdf",
    "versionId": "version-id-from-s3",
    "size": 2048576,
    "contentType": "application/pdf",
    "uploadedAt": "2025-11-14T10:30:00.000Z",
    "metadata": {
      "source": "client-portal",
      "tag": "contracts"
    }
  }
}
```

**Error Response (400/500):**

```json
{
  "success": false,
  "error": {
    "code": "FILE_TOO_LARGE",
    "message": "File size exceeds maximum allowed size of 100MB",
    "details": {
      "filename": "document.pdf",
      "fileSize": 125829120,
      "maxSize": 104857600
    },
    "timestamp": "2025-11-14T10:30:00.000Z",
    "requestId": "uuid-v4"
  }
}
```

**curl Example:**

```bash
curl -X POST http://localhost:3000/api/v1/upload \
  -H "X-API-Key: your-api-key-here" \
  -F "file=@/path/to/document.pdf" \
  -F "source=client-portal" \
  -F "tag=contracts"
```

---

#### 3. Batch File Upload

Upload multiple files in a single request.

**Endpoint:** `POST /api/v1/upload/batch`

**Authentication:** Required

**Content-Type:** `multipart/form-data`

**Parameters:**

| Field    | Type   | Required | Description                 |
| -------- | ------ | -------- | --------------------------- |
| `files`  | file[] | Yes      | Array of files (max 10)     |
| `source` | string | No       | Source folder for all files |
| `tag`    | string | No       | Tag subfolder for all files |

**Success Response (200):**

```json
{
  "success": true,
  "data": {
    "total": 3,
    "successful": 2,
    "failed": 1,
    "results": [
      {
        "filename": "doc1.pdf",
        "success": true,
        "data": {
          "uploadId": "uuid",
          "s3Location": "s3://bucket/path/doc1.pdf",
          "size": 1024000
        }
      },
      {
        "filename": "doc2.pdf",
        "success": true,
        "data": {
          "uploadId": "uuid",
          "s3Location": "s3://bucket/path/doc2.pdf",
          "size": 2048000
        }
      },
      {
        "filename": "large.pdf",
        "success": false,
        "error": {
          "code": "FILE_TOO_LARGE",
          "message": "File size exceeds maximum allowed size"
        }
      }
    ]
  }
}
```

**curl Example:**

```bash
curl -X POST http://localhost:3000/api/v1/upload/batch \
  -H "X-API-Key: your-api-key-here" \
  -F "files=@/path/to/doc1.pdf" \
  -F "files=@/path/to/doc2.pdf" \
  -F "files=@/path/to/doc3.pdf" \
  -F "source=documents" \
  -F "tag=invoices"
```

---

### Error Codes Reference

| Code                | HTTP Status | Description                            |
| ------------------- | ----------- | -------------------------------------- |
| `MISSING_API_KEY`   | 401         | No API key provided in request         |
| `INVALID_API_KEY`   | 401         | API key is invalid or expired          |
| `MISSING_FILE`      | 400         | No file attached to request            |
| `FILE_TOO_LARGE`    | 400         | File exceeds MAX_FILE_SIZE             |
| `REQUEST_TOO_LARGE` | 400         | Total request exceeds MAX_REQUEST_SIZE |
| `INVALID_FILE_TYPE` | 400         | File type not in ALLOWED_FILE_TYPES    |
| `INVALID_FILENAME`  | 400         | Filename contains invalid characters   |
| `VIRUS_DETECTED`    | 400         | File failed virus scan                 |
| `S3_UPLOAD_FAILED`  | 500         | Error uploading to S3                  |
| `VALIDATION_FAILED` | 400         | Generic validation error               |
| `INTERNAL_ERROR`    | 500         | Unexpected server error                |

---

## Deployment

### AWS S3 Setup

1. **Create S3 Bucket:**

```bash
aws s3 mb s3://your-bucket-name --region us-east-1
```

2. **Enable Versioning:**

```bash
aws s3api put-bucket-versioning \
  --bucket your-bucket-name \
  --versioning-configuration Status=Enabled
```

3. **Create IAM User and Policy:**

IAM Policy (minimal permissions):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "s3:PutObject",
        "s3:PutObjectAcl",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:PutObjectTagging"
      ],
      "Resource": [
        "arn:aws:s3:::your-bucket-name",
        "arn:aws:s3:::your-bucket-name/*"
      ]
    }
  ]
}
```

4. **Generate Access Keys:**

```bash
aws iam create-access-key --user-name file-api-user
```

---

### Cloud Deployment Examples

#### AWS EC2

```bash
# SSH into EC2 instance
ssh -i your-key.pem ec2-user@your-instance

# Install Docker
sudo yum update -y
sudo yum install docker -y
sudo service docker start
sudo usermod -a -G docker ec2-user

# Install Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# Clone and deploy
git clone <your-repo>
cd file-api
cp .env.example .env
# Edit .env with your settings
docker-compose up -d
```

#### DigitalOcean Droplet

```bash
# Create droplet with Docker preinstalled
# SSH into droplet
ssh root@your-droplet-ip

# Clone and deploy
git clone <your-repo>
cd file-api
cp .env.example .env
# Edit .env with your settings
docker-compose up -d

# Setup firewall
ufw allow 3000/tcp
ufw enable
```

#### Google Cloud Platform (GCE)

```bash
# Create VM instance
gcloud compute instances create file-api \
  --machine-type=e2-medium \
  --zone=us-central1-a

# SSH and deploy
gcloud compute ssh file-api
# Follow EC2 steps above
```

---

### Reverse Proxy (Nginx)

For production, use Nginx as reverse proxy:

```nginx
server {
    listen 80;
    server_name api.yourdomain.com;

    client_max_body_size 500M;

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_cache_bypass $http_upgrade;

        # Timeouts for large uploads
        proxy_connect_timeout 600;
        proxy_send_timeout 600;
        proxy_read_timeout 600;
        send_timeout 600;
    }
}
```

---

## Testing

### Manual Testing

#### Test Single Upload:

```bash
# Create test file
echo "Test content" > test.txt

# Upload
curl -X POST http://localhost:3000/api/v1/upload \
  -H "X-API-Key: your-api-key" \
  -F "file=@test.txt" \
  -F "source=test" \
  -F "tag=manual"
```

#### Test Batch Upload:

```bash
# Create multiple test files
echo "File 1" > file1.txt
echo "File 2" > file2.txt
echo "File 3" > file3.txt

# Upload batch
curl -X POST http://localhost:3000/api/v1/upload/batch \
  -H "X-API-Key: your-api-key" \
  -F "files=@file1.txt" \
  -F "files=@file2.txt" \
  -F "files=@file3.txt" \
  -F "source=test" \
  -F "tag=batch"
```

#### Test Error Handling:

```bash
# Test invalid API key
curl -X POST http://localhost:3000/api/v1/upload \
  -H "X-API-Key: invalid-key" \
  -F "file=@test.txt"

# Test file too large (create 150MB file if MAX_FILE_SIZE=100MB)
dd if=/dev/zero of=large.dat bs=1M count=150
curl -X POST http://localhost:3000/api/v1/upload \
  -H "X-API-Key: your-api-key" \
  -F "file=@large.dat"

# Test invalid file type
echo "test" > test.exe
curl -X POST http://localhost:3000/api/v1/upload \
  -H "X-API-Key: your-api-key" \
  -F "file=@test.exe"
```

#### Test Health Check:

```bash
curl http://localhost:3000/health
```

### Verify S3 Upload:

```bash
# List objects in bucket
aws s3 ls s3://your-bucket-name/test/manual/ --recursive

# Download uploaded file
aws s3 cp s3://your-bucket-name/test/manual/2025-11-14T10-30-00_test.txt ./downloaded.txt
```

---

## Troubleshooting

### Common Issues

#### 1. ClamAV Not Starting

**Symptom:** API can't connect to virus scanner

**Solution:**

```bash
# Check ClamAV logs
docker-compose logs clamav

# ClamAV takes time to download virus definitions
# Wait 2-3 minutes after first start

# Check ClamAV status
docker-compose exec clamav clamdscan --version
```

#### 2. S3 Upload Fails

**Symptom:** `S3_UPLOAD_FAILED` error

**Solutions:**

```bash
# Verify AWS credentials
aws s3 ls s3://your-bucket-name

# Check IAM permissions
# Ensure policy includes PutObject, PutObjectTagging

# Test connectivity from container
docker-compose exec api sh
apk add curl
curl https://s3.amazonaws.com
```

#### 3. API Key Not Generated

**Symptom:** No API key in logs

**Solution:**

```bash
# Check data volume permissions
ls -la ./data/

# Manually check key file
cat ./data/api-key.txt

# Generate new key manually
docker-compose exec api node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

#### 4. File Upload Hangs

**Symptom:** Upload never completes

**Solutions:**

- Check file size against MAX_FILE_SIZE
- Verify network timeout settings
- Check Docker memory limits:

```bash
docker stats
```

- Increase Docker memory if needed

#### 5. Permission Denied Errors

**Symptom:** Can't write to logs or data directories

**Solution:**

```bash
# Fix permissions
chmod 755 ./data ./logs
chown -R 1001:1001 ./data ./logs

# Or run as root (not recommended for production)
# Edit docker-compose.yml and add: user: "0:0"
```

---

## Security

### Best Practices

1. **API Key Management:**

   - Never commit API keys to git
   - Rotate keys regularly
   - Use different keys per environment
   - Store keys in secrets manager for production

2. **Network Security:**

   - Use HTTPS in production (terminate SSL at load balancer/reverse proxy)
   - Restrict API access by IP if possible
   - Use VPC/private networks for cloud deployments

3. **S3 Security:**

   - Use IAM roles instead of access keys when possible
   - Enable S3 bucket encryption
   - Enable S3 access logging
   - Block public access to bucket

4. **File Security:**

   - Keep virus definitions updated (ClamAV auto-updates)
   - Review ALLOWED_FILE_TYPES regularly
   - Set reasonable size limits
   - Monitor for suspicious upload patterns

5. **Container Security:**

   - Keep base images updated
   - Scan images for vulnerabilities
   - Run containers as non-root user (already implemented)
   - Use Docker secrets for sensitive data

### Production Checklist

- [ ] Change default API key
- [ ] Enable HTTPS
- [ ] Configure firewall rules
- [ ] Set up monitoring and alerts
- [ ] Configure log rotation
- [ ] Enable S3 bucket encryption
- [ ] Set up backup strategy
- [ ] Configure rate limiting appropriately
- [ ] Review and restrict CORS settings
- [ ] Set up health check monitoring
- [ ] Document incident response procedures

---

## Monitoring

### Logs

View logs:

```bash
# All logs
docker-compose logs -f

# API logs only
docker-compose logs -f api

# Last 100 lines
docker-compose logs --tail=100 api
```

### Metrics

Access metrics (if enabled):

```
http://localhost:3000/metrics
```

### Health Monitoring

Set up automated health checks:

```bash
# Simple cron job
*/5 * * * * curl -f http://localhost:3000/health || echo "API Down" | mail -s "Alert" admin@example.com
```

---

## License

MIT License - See LICENSE file for details

---

## Support

For issues and questions:

- Create an issue in the repository
- Check existing issues for solutions
- Review logs for detailed error messages

---

## Changelog

### v1.0.0 (2025-11-14)

- Initial release
- Single and batch file uploads
- Virus scanning integration
- S3 storage with versioning
- Docker containerization
- Comprehensive error handling

````

---

## STEP 11: FINAL IMPLEMENTATION NOTES

### Testing Your Complete Build

After implementing all steps, test the complete system:

1. **Build and Start:**
```bash
docker-compose up --build
````

2. **Verify Startup:**

- Check logs for API key
- Verify ClamAV started (may take 2-3 minutes)
- Check health endpoint returns "ok"

3. **Test Upload Flow:**

- Single file upload
- Batch upload
- Invalid file type
- File too large
- Invalid API key
- Virus scan (use EICAR test file)

4. **Verify S3 Storage:**

- Check folder structure matches pattern
- Verify file metadata
- Verify tags are applied
- Check versioning (upload same file twice)

### Performance Considerations

- Chunk size affects memory usage and speed
- Concurrent upload limit prevents resource exhaustion
- Multer uses memory storage - large files may need disk storage for very constrained environments
- ClamAV virus scanning adds latency (typically 1-3 seconds per file)

### Scalability Options

For high-volume deployments:

1. Deploy multiple API instances behind load balancer
2. Use separate ClamAV cluster
3. Implement Redis for distributed rate limiting
4. Add queue system (Bull/BullMQ) for async processing
5. Use CloudFront CDN for large file downloads

### Code Quality Standards

Ensure the generated code follows:

- ESLint best practices
- Consistent error handling patterns
- Proper async/await usage (no unhandled promises)
- Descriptive variable and function names
- Comments for complex logic only
- DRY principle (no code duplication)

### Deliverables Checklist

Ensure LLM generates ALL of:

- [ ] Complete source code (all files in structure)
- [ ] Dockerfile with multi-stage build
- [ ] docker-compose.yml with both services
- [ ] .env.example with all variables
- [ ] .dockerignore
- [ ] .gitignore
- [ ] package.json with exact dependencies
- [ ] Complete README.md with all sections
- [ ] All code properly commented
- [ ] Error handling in every async function
- [ ] Logging at appropriate levels
- [ ] Security best practices implemented

---

## CRITICAL REQUIREMENTS SUMMARY

**DO NOT OMIT:**

1. Human-readable size parsing (parseSize utility)
2. API key auto-generation and persistence
3. Complete error handling with custom error classes
4. S3 folder structure: `{source}/{tag}/{timestamp}_{filename}`
5. S3 metadata and tagging
6. Virus scanning with ClamAV integration
7. Batch upload with concurrent processing
8. File validation (name, type, size)
9. Winston logging with daily rotation
10. Health check with S3 connectivity test
11. Docker multi-stage build
12. Non-root container user
13. Rate limiting
14. Request ID tracking
15. Graceful shutdown handling
16. Complete README with examples
17. All environment variables configurable
18. Security headers (Helmet)
19. CORS configuration
20. Comprehensive error responses

**IMPLEMENTATION ORDER:** Follow steps 1-11 sequentially. Each step builds on previous steps. Do not skip ahead.

**CODE STYLE:**

- Use async/await, not callbacks or raw promises
- Use const/let, never var
- Destructure where appropriate
- Use template literals for strings
- Proper indentation (2 spaces)
- Semicolons at end of statements

**TESTING REQUIREMENTS:** After implementing, the system must:

- Start successfully with `docker-compose up`
- Log API key on first run
- Accept valid file uploads
- Reject invalid API keys
- Reject invalid file types
- Reject oversized files
- Detect viruses (test with EICAR)
- Upload to S3 with correct structure
- Return proper error messages
- Pass health check

This blueprint provides complete, step-by-step instructions for building the entire system. Follow it precisely to create a production-ready file API.
