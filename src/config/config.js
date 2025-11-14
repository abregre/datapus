console.log("CONFIG: Starting config loading...");
const { parseSize } = require("../utils/sizeParser");
console.log("CONFIG: sizeParser loaded.");

// Load environment variables
console.log("CONFIG: Loading dotenv config...");
require("dotenv").config();
console.log("CONFIG: dotenv config loaded.");

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

console.log("CONFIG: File size and request size parsed.");

// Validation
console.log("CONFIG: Starting validation...");
if (!config.aws.accessKeyId) {
  console.error("CONFIG ERROR: AWS_ACCESS_KEY_ID environment variable is required");
  throw new Error("AWS_ACCESS_KEY_ID environment variable is required");
}

if (!config.aws.secretAccessKey) {
  console.error("CONFIG ERROR: AWS_SECRET_ACCESS_KEY environment variable is required");
  throw new Error("AWS_SECRET_ACCESS_KEY environment variable is required");
}

if (!config.aws.bucketName) {
  console.error("CONFIG ERROR: S3_BUCKET_NAME environment variable is required");
  throw new Error("S3_BUCKET_NAME environment variable is required");
}
console.log("CONFIG: Validation passed.");

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
console.log("CONFIG: Configuration object exported.");

module.exports = config;
