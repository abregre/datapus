const multer = require("multer");
const config = require("../config/config");
const fileValidator = require("../services/fileValidator");
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
  // For /api/v1/upload/url endpoint, file is fetched from URL, not directly uploaded
  if (req.originalUrl === "/api/v1/upload/url") {
    const { url } = req.body;
    if (!url) {
      return next(
        new ValidationError("MISSING_URL", "File URL is required in request body")
      );
    }
    // Proceed to next middleware/route handler, as file validation will happen after fetching
    return next();
  }

  // For other upload endpoints, check if file exists in req.file or req.files
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
