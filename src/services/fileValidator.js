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
