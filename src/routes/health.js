const express = require("express");
const router = express.Router();
const s3Service = require("../services/s3Service");
const config = require("../config/config");
const NodeClam = require("clamscan");

router.get("/", async (req, res) => {
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

module.exports = router;
