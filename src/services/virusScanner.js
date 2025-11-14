const NodeClam = require("clamscan");
const fs = require("fs").promises;
const { tmpdir } = require("os");
const { join } = require("path");
const { VirusScanError } = require("../utils/errors");

let clamScanner = null;

/**
 * Initialize the ClamAV scanner
 * @param {Object} config - Application configuration
 * @returns {Promise<Object|null>} Initialized scanner or null if disabled
 */
async function initializeScanner(config) {
  if (!config.virusScan.enabled) {
    return null;
  }

  let retries = 10; // Increased retries
  let delay = 10000; // Increased delay to 10 seconds

  for (let i = 0; i < retries; i++) {
    try {
      console.log(`ClamAV: Attempting to initialize scanner (attempt ${i + 1}/${retries})...`);
      clamScanner = await new NodeClam().init({
        clamdscan: {
          host: config.virusScan.host,
          port: config.virusScan.port,
          timeout: 120000, // Increased timeout to 2 minutes
          // Add debug logging for NodeClam if available
          // debugMode: true,
        },
        preference: "clamdscan",
      });

      console.log(`ClamAV: Scanner initialized successfully (attempt ${i + 1})`);
      return clamScanner;
    } catch (error) {
      console.error(`ClamAV: Initialization attempt ${i + 1} failed:`, error.message);
      if (i < retries - 1) {
        console.log(`ClamAV: Retrying in ${delay / 1000} seconds...`);
        await new Promise(resolve => setTimeout(resolve, delay));
      } else {
        console.error(`ClamAV: All ${retries} initialization attempts failed. Last error:`, error);
        throw new Error(`ClamAV initialization failed after ${retries} attempts: ${error.message}`);
      }
    }
  }
}

/**
 * Scan a file for viruses
 * @param {string} filePath - Path to the file to scan
 * @returns {Promise<Object>} Scan results { isInfected: boolean, viruses: array }
 */
async function scanFile(filePath) {
  if (!clamScanner) {
    return { isInfected: false };
  }

  try {
    const { isInfected, viruses } = await clamScanner.scanFile(filePath);

    console.log(
      `Virus scan completed for ${filePath}: infected=${isInfected}`,
      { viruses }
    );

    if (isInfected && viruses && viruses.length > 0) {
      throw new VirusScanError(`Virus detected: ${viruses.join(", ")}`);
    }

    return { isInfected, viruses: viruses || [] };
  } catch (error) {
    console.error(`Virus scan failed for file ${filePath}:`, error);
    throw error;
  }
}

/**
 * Scan a buffer for viruses by writing to a temporary file
 * @param {Buffer} buffer - Buffer to scan
 * @returns {Promise<Object>} Scan results { isInfected: boolean, viruses: array }
 */
async function scanBuffer(buffer) {
  if (!clamScanner) {
    return { isInfected: false };
  }

  let tempFilePath;

  try {
    // Create a temporary file
    const tempFileName = `temp_scan_${Date.now()}_${Math.random()
      .toString(36)
      .substring(2, 15)}`;
    tempFilePath = join(tmpdir(), tempFileName);

    // Write buffer to temp file
    await fs.writeFile(tempFilePath, buffer);

    // Scan the temp file
    const result = await scanFile(tempFilePath);

    return result;
  } catch (error) {
    console.error("Buffer scan failed:", error);
    throw error;
  } finally {
    // Clean up temp file if it was created
    if (tempFilePath) {
      try {
        await fs.unlink(tempFilePath);
      } catch (unlinkError) {
        console.warn(
          `Failed to delete temporary file ${tempFilePath}:`,
          unlinkError.message
        );
      }
    }
  }
}

module.exports = {
  initializeScanner,
  scanFile,
  scanBuffer,
};
