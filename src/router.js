"use strict";

/**
 * HTTP router with parameter extraction.
 *
 * Supports path parameters (`:param`) and a trailing wildcard (`*`).
 * Routes are matched against registered HTTP methods and paths.
 * Named parameters are extracted into `req.params`.
 *
 * @module router
 * @private
 */

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/**
 * Compiles a route path into a RegExp and a list of parameter names.
 *
 * @param {string} path - Route path (e.g., `/users/:id` or `/files/*`)
 * @returns {{ regex: RegExp, paramNames: string[] }}
 * @private
 */
function compilePath(path) {
  const paramNames = [];
  const WILDCARD = "\x00OBSIDIAN\x00";

  const pattern = path
    .replace(/\*/g, WILDCARD)
    .replace(/[-[\]{}()+?.,\\^$|#\s]/g, "\\$&")
    .replace(new RegExp(WILDCARD, "g"), "(.*)")
    .replace(/:([a-zA-Z_][a-zA-Z0-9_]*)/g, (_, name) => {
      paramNames.push(name);
      return "([^/]+)";
    });

  return {
    regex: new RegExp(`^${pattern}$`),
    paramNames,
  };
}

/**
 * Router class.
 */
class Router {
  constructor() {
    /** @private {Array<object>} */
    this._routes = [];
  }

  /**
   * Registers a route.
   *
   * @param {string} method - HTTP method (case‑insensitive)
   * @param {string} path - Route path
   * @param {Function} handler - Async (req, res) => void
   * @param {boolean} [isPublic=false] - Whether the route is public (no encryption)
   * @returns {this}
   */
  on(method, path, handler, isPublic = false) {
    const { regex, paramNames } = compilePath(path);
    this._routes.push({
      method: method.toUpperCase(),
      regex,
      paramNames,
      handler,
      public: isPublic,
    });
    return this;
  }

  /**
   * Matches a request against registered routes.
   *
   * @param {string} method - HTTP method
   * @param {string} pathname - Request path
   * @returns {object|null} Matched route data or null
   */
  match(method, pathname) {
    for (const route of this._routes) {
      if (route.method !== method.toUpperCase()) continue;

      const match = pathname.match(route.regex);
      if (!match) continue;

      const params = {};
      route.paramNames.forEach((name, index) => {
        params[name] = decodeURIComponent(match[index + 1]);
      });

      return {
        handler: route.handler,
        params,
        public: route.public || false,
      };
    }
    return null;
  }
}

// Convenience methods: router.get(), router.post(), etc.
METHODS.forEach((verb) => {
  Router.prototype[verb.toLowerCase()] = function (path, handler) {
    return this.on(verb, path, handler, false);
  };
});

module.exports = { Router };
