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
