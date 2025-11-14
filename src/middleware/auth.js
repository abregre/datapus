const apiKeyManager = require("../services/apiKeyManager");
const { AuthenticationError } = require("../utils/errors");

/**
 * Middleware to authenticate requests using API key
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
async function authenticate(req, res, next) {
  const apiKey = req.headers["x-api-key"];

  if (!apiKey) {
    return next(new AuthenticationError("Missing API key"));
  }

  const isValid = await apiKeyManager.validateApiKey(apiKey);

  if (!isValid) {
    return next(new AuthenticationError("Invalid API key"));
  }

  next();
}

module.exports = { authenticate };
