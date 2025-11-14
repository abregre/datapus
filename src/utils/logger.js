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
