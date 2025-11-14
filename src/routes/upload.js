const express = require("express");
const router = express.Router();
const { v4: uuid } = require("uuid");
const config = require("../config/config");
const logger = require("../utils/logger");
const fileValidator = require("../services/fileValidator");
const virusScanner = require("../services/virusScanner");
const s3Service = require("../services/s3Service");
const { VirusScanError } = require("../utils/errors");
const { authenticate } = require("../middleware/auth");
const { setupMulter, validateUploadRequest } = require("../middleware/validation");

const upload = setupMulter();

// Single file upload
router.post(
  "/upload",
  authenticate,
  upload.single("file"),
  validateUploadRequest,
  async (req, res, next) => {
    try {
      const file = req.file;
      const { source, tag } = req.body;

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
            `Virus detected: ${scanResult.viruses.join(", ")}`
          );
        }
      }

      // Generate S3 key
      const s3Key = s3Service.generateS3Key(
        source || config.defaultSourceFolder,
        tag || "general",
        sanitizedName
      );

      // Upload to S3
      const uploadResult = await s3Service.uploadFile(
        file.buffer,
        s3Key,
        {
          contentType: file.mimetype,
          originalFilename: file.originalname,
          sourceIp: req.ip,
          size: file.size,
        },
        {
          source: source || config.defaultSourceFolder,
          tag: tag || "general",
          "upload-date": new Date().toISOString().split("T")[0],
          "content-type": file.mimetype,
        }
      );

      // Log successful upload
      logger.info("File uploaded successfully", {
        filename: sanitizedName,
        size: file.size,
        s3Key,
        source,
        tag,
      });

      // Return success response
      res.json({
        success: true,
        data: {
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
            tag: tag || "general",
          },
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

// Batch file upload
router.post(
  "/upload/batch",
  authenticate,
  upload.array("files", 10),
  validateUploadRequest,
  async (req, res, next) => {
    try {
      const files = req.files;
      const { source, tag } = req.body;

      // Validate total batch size
      fileValidator.validateBatchSize(files, config.maxRequestSize);

      // Process files concurrently (with limit)
      const results = [];
      const chunks = [];

      // Split files into chunks based on maxConcurrentUploads
      for (let i = 0; i < files.length; i += config.maxConcurrentUploads) {
        chunks.push(files.slice(i, i + config.maxConcurrentUploads));
      }

      // Process each chunk
      for (const chunk of chunks) {
        const chunkResults = await Promise.allSettled(
          chunk.map((file) => processFile(file, source, tag, req.ip))
        );

        // Map results
        chunkResults.forEach((result, index) => {
          if (result.status === "fulfilled") {
            results.push({
              filename: chunk[index].originalname,
              success: true,
              data: result.value,
            });
          } else {
            results.push({
              filename: chunk[index].originalname,
              success: false,
              error: {
                code: result.reason.code || "UPLOAD_FAILED",
                message: result.reason.message,
              },
            });
          }
        });
      }

      // Count successes and failures
      const successful = results.filter((r) => r.success).length;
      const failed = results.filter((r) => !r.success).length;

      // Return batch results
      res.json({
        success: true,
        data: {
          total: files.length,
          successful,
          failed,
          results,
        },
      });
    } catch (error) {
      next(error);
    }
  }
);

async function processFile(file, source, tag, ip) {
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
        `Virus detected: ${scanResult.viruses.join(", ")}`
      );
    }
  }

  // Generate S3 key
  const s3Key = s3Service.generateS3Key(
    source || config.defaultSourceFolder,
    tag || "general",
    sanitizedName
  );

  // Convert buffer to readable stream for efficient upload
  const bufferStream = require("stream").Readable.from(file.buffer);

  // Upload to S3
  const uploadResult = await s3Service.uploadFile(
    bufferStream,
    s3Key,
    {
      contentType: file.mimetype,
      originalFilename: file.originalname,
      sourceIp: ip,
      size: file.size,
    },
    {
      source: source || config.defaultSourceFolder,
      tag: tag || "general",
      "upload-date": new Date().toISOString().split("T")[0],
      "content-type": file.mimetype,
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
      tag: tag || "general",
    },
  };
}

module.exports = router;
