"use strict";

/**
 * Unified authentication middleware for Obsidiana.
 *
 * Resolves user identity from three sources:
 * - "auth" cookie (web browsers)
 * - Bearer token (API clients)
 * - Token field in request body (mobile apps)
 *
 * Decrypts the credential using the identity key and attaches the user data
 * to `req.user`. Also sets `req.isAuthenticated` and `req.authMethod`.
 *
 * @module auth
 * @private
 */

/**
 * Factory that creates the unified authentication middleware.
 *
 * @param {ObsidianaCookieManager} cookieManager - Manager for encrypted cookies
 * @param {ObsidianaTokenManager} tokenManager - Manager for stateless tokens
 * @returns {Function} Express-style middleware (req, res, next) => Promise<void>
 */
function createAuthMiddleware(cookieManager, tokenManager) {
  return async function authMiddleware(req, res, next) {
    let userData = null;
    let authMethod = null;

    // 1) Try to read and decrypt the "auth" cookie
    if (cookieManager && !userData) {
      const cookieAuth = await cookieManager.get(req, "auth");
      if (cookieAuth?.userId) {
        userData = cookieAuth;
        authMethod = "cookie";
      }
    }

    // 2) Try Bearer token from Authorization header
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

    // 3) Try token from request body (mobile apps)
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
 * Wraps a route handler to require authentication.
 *
 * Responds with 401 if the request is not authenticated.
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
 * Wraps a route handler for optional authentication.
 *
 * Does not block unauthenticated requests; simply attaches `req.user`
 * if authentication data is present.
 *
 * @param {Function} handler - Route handler (req, res) => Promise<void>
 * @returns {Function} Wrapped handler
 */
function optionalAuth(handler) {
  return async (req, res) => handler(req, res);
}

module.exports = {
  createAuthMiddleware,
  requireAuth,
  optionalAuth,
};
