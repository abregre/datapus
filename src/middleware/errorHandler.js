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
