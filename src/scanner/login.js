/**
 * Login entrypoint — delegates to auth adapter orchestrator.
 * Kept at src/scanner/login.js for backward-compatible requires.
 */
const {
  loginWithCredentials,
  extractToken,
  detectAuthStrategies,
  assertSessionReady,
} = require('./auth');

module.exports = {
  loginWithCredentials,
  extractToken,
  detectAuthStrategies,
  assertSessionReady,
};
