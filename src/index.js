const express = require("express");
const helmet = require("helmet");
const cors = require("cors");
const rateLimit = require("express-rate-limit");
const { v4: uuid } = require("uuid");

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
  try {
    logger.info("Starting File API service...");

    // Load or generate API key
    const apiKeyFilePath = "./data/api-key.txt";
    let apiKey;
    try {
      apiKey = await apiKeyManager.validateApiKey(process.env.API_KEY);
    } catch (e) {
      //
    }

    if (!apiKey && process.env.API_KEY) {
      apiKey = process.env.API_KEY;
      require("fs").writeFileSync(apiKeyFilePath, apiKey);
    } else {
      apiKey = apiKeyManager.generateApiKey();
      require("fs").writeFileSync(apiKeyFilePath, apiKey);
    }

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
