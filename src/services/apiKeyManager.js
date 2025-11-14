const crypto = require("crypto");
const fs = require("fs").promises;
const path = require("path");

/**
 * Generate a cryptographically secure random API key
 * @returns {string} Hex-encoded API key (64 characters)
 */
function generateApiKey() {
  return crypto.randomBytes(32).toString("hex");
}

/**
 * Validate an API key against the stored key using timing-safe comparison
 * @param {string} providedKey - The key to validate
 * @returns {Promise<boolean>} True if valid, false otherwise
 */
async function validateApiKey(providedKey) {
  if (!providedKey) {
    return false;
  }

  const apiKeyPath = path.join(__dirname, "../../data/api-key.txt");

  try {
    const storedKey = await fs.readFile(apiKeyPath, "utf8");
    const trimmedStoredKey = storedKey.trim();

    if (trimmedStoredKey.length !== providedKey.length) {
      return false;
    }

    // Use timing-safe comparison to prevent timing attacks
    const bufferA = Buffer.from(trimmedStoredKey, "utf8");
    const bufferB = Buffer.from(providedKey, "utf8");

    return crypto.timingSafeEqual(bufferA, bufferB);
  } catch (error) {
    console.error("Error validating API key:", error.message);
    return false;
  }
}

module.exports = {
  generateApiKey,
  validateApiKey,
};
