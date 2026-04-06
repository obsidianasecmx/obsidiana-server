"use strict";

/**
 * Obsidiana Auth Middleware — Unified authentication middleware.
 *
 * Resolves authentication from three sources:
 * 1. "auth" cookie (web browsers)
 * 2. Bearer token (API clients)
 * 3. Token in request body (mobile apps)
 *
 * Automatically decrypts the token/cookie and attaches the user data to
 * `req.user`. Also sets `req.isAuthenticated` flag.
 *
 * @module auth
 * @private
 */

/**
 * Creates the unified authentication middleware.
 *
 * @param {ObsidianaCookieManager} cookieManager - Cookie manager for auth cookie
 * @param {ObsidianaTokenManager} tokenManager - Token manager for Bearer/body tokens
 * @returns {Function} Express-style middleware (req, res, next) => Promise<void>
 */
function createAuthMiddleware(cookieManager, tokenManager) {
  return async function authMiddleware(req, res, next) {
    let userData = null;
    let authMethod = null;

    if (cookieManager && !userData) {
      const cookieAuth = await cookieManager.get(req, "auth");
      if (cookieAuth?.userId) {
        userData = cookieAuth;
        authMethod = "cookie";
      }
    }

    if (!userData && req.headers.authorization) {
      const match = req.headers.authorization.match(/^Bearer\s+(.+)$/i);
      if (match) {
        const tokenData = await tokenManager.verify(match[1]);
        if (tokenData?.userId) {
          userData = tokenData;
          authMethod = "bearer";
        }
      }
    }

    if (!userData && req.body?.token) {
      const tokenData = await tokenManager.verify(req.body.token);
      if (tokenData?.userId) {
        userData = tokenData;
        authMethod = "body";
      }
    }

    req.user = userData;
    req.authMethod = authMethod;
    req.isAuthenticated = !!userData;

    next();
  };
}

/**
 * Middleware wrapper that requires authentication.
 *
 * @param {Function} handler - Route handler (req, res) => Promise<void>
 * @returns {Function} Wrapped handler that checks authentication first
 */
function requireAuth(handler) {
  return async (req, res) => {
    if (!req.isAuthenticated) {
      return res.send(401);
    }
    return handler(req, res);
  };
}

/**
 * Middleware wrapper for optional authentication.
 *
 * @param {Function} handler - Route handler (req, res) => Promise<void>
 * @returns {Function} Wrapped handler
 */
function optionalAuth(handler) {
  return async (req, res) => handler(req, res);
}

/**
 * @exports
 * @property {Function} createAuthMiddleware - Creates auth middleware
 * @property {Function} requireAuth - Wraps handler to require authentication
 * @property {Function} optionalAuth - Wraps handler for optional authentication
 */
module.exports = {
  createAuthMiddleware,
  requireAuth,
  optionalAuth,
};
