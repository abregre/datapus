const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { v4: uuid } = require("uuid");

// Load config
console.log("DATAPUS: Loading dotenv config in index.js...");
require("dotenv").config();
console.log("DATAPUS: dotenv config loaded in index.js.");

console.log("DATAPUS: Requiring config...");
const config = require("./config/config");
console.log("DATAPUS: Config loaded.");

console.log("DATAPUS: Requiring logger...");
const logger = require("./utils/logger");
console.log("DATAPUS: Logger loaded.");

// Services
console.log("DATAPUS: Requiring apiKeyManager...");
const apiKeyManager = require("./services/apiKeyManager");
console.log("DATAPUS: apiKeyManager loaded.");

console.log("DATAPUS: Requiring virusScanner...");
const virusScanner = require("./services/virusScanner");
console.log("DATAPUS: virusScanner loaded.");

// Routes
console.log("DATAPUS: Requiring uploadRoutes...");
const uploadRoutes = require("./routes/upload");
console.log("DATAPUS: uploadRoutes loaded.");

console.log("DATAPUS: Requiring healthRoutes...");
const healthRoutes = require("./routes/health");
console.log("DATAPUS: healthRoutes loaded.");

// Middleware
const { errorHandler } = require("./middleware/errorHandler");

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
  console.log("DATAPUS: Starting startup sequence...");
  try {
    logger.info("Starting File API service...");
    console.log("DATAPUS: Logger initialized.");

    // Load or generate API key
    const apiKeyFilePath = "./data/api-key.txt";
    let apiKey;
    console.log("DATAPUS: Attempting to load/generate API key...");
    try {
      apiKey = await apiKeyManager.validateApiKey(process.env.API_KEY);
    } catch (e) {
      console.log("DATAPUS: API key validation failed or not provided, generating new key.");
      //
    }

    if (!apiKey && process.env.API_KEY) {
      apiKey = process.env.API_KEY;
      require("fs").writeFileSync(apiKeyFilePath, apiKey);
    } else {
      apiKey = apiKeyManager.generateApiKey();
      require("fs").writeFileSync(apiKeyFilePath, apiKey);
    }
    console.log("DATAPUS: API key operation completed.");

    logger.info("API Key loaded", {
      key: apiKey.substring(0, 8) + "...",
    });
    console.log("\n========================================");
    console.log("API KEY:", apiKey);
    console.log("========================================\n");

    // Initialize virus scanner
    if (config.virusScan.enabled) {
      logger.info("Initializing virus scanner...");
      console.log("DATAPUS: Calling virusScanner.initializeScanner...");
      await virusScanner.initializeScanner(config);
      logger.info("Virus scanner initialized");
      console.log("DATAPUS: Virus scanner initialized successfully.");
    } else {
      logger.warn("Virus scanning is DISABLED");
      console.log("DATAPUS: Virus scanning is disabled.");
    }

    // Start server
    console.log(`DATAPUS: Attempting to start server on port ${config.port}...`);
    const server = app.listen(config.port, () => {
      logger.info(`Server running on port ${config.port}`);
      logger.info(`Environment: ${config.nodeEnv}`);
      logger.info(`S3 Bucket: ${config.aws.bucketName}`);
      console.log("DATAPUS: Server started successfully.");
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
    logger.error("Failed to start service", { error });
    console.error("DATAPUS: Unhandled error in startup sequence:", error);
    process.exit(1);
  }
}

// Catch unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('DATAPUS: Unhandled Rejection at:', promise, 'reason:', reason);
  process.exit(1);
});

// Catch uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('DATAPUS: Uncaught Exception:', error);
  process.exit(1);
});

// Start the application
startup();
