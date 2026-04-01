"use strict";

/**
 * Obsidiana Router — HTTP route matching and parameter extraction.
 *
 * A lightweight router that supports path parameters (`:param`) and a
 * trailing wildcard (`*`). Routes are matched against registered HTTP
 * methods and paths, extracting named parameters into `req.params`.
 *
 * @module router
 * @private
 */

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/**
 * Compiles a route path string into a regular expression and a list of
 * parameter names.
 *
 * Supports:
 * - `:param` — captures a single path segment (excludes `/`)
 * - `*` — captures the remainder of the path (must appear at the end)
 *
 * @param {string} path - Route path with optional parameters
 * @returns {{ regex: RegExp, paramNames: string[] }} Compiled regex and param names
 * @private
 */
function compilePath(path) {
  const paramNames = [];

  // Placeholder to protect wildcard from regex escaping
  const WILDCARD = "\x00OBSIDIAN\x00";

  const pattern = path
    // Temporarily replace * with placeholder
    .replace(/\*/g, WILDCARD)
    // Escape regex special characters
    .replace(/[-[\]{}()+?.,\\^$|#\s]/g, "\\$&")
    // Restore wildcard as capture group (.*)
    .replace(new RegExp(WILDCARD, "g"), "(.*)")
    // Replace :param with capture group ([^/]+)
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
 * HTTP router with parameter extraction and method-based routing.
 *
 * @example
 * const router = new Router();
 * router.get('/users/:id', (req, res) => {
 *   const userId = req.params.id;
 *   // ...
 * });
 *
 * const match = router.match('GET', '/users/42');
 * if (match) {
 *   await match.handler(req, res); // req.params = { id: '42' }
 * }
 */
class Router {
  constructor() {
    /**
     * Internal route registry.
     * @private
     * @type {Array<{
     *   method: string,
     *   regex: RegExp,
     *   paramNames: string[],
     *   handler: Function,
     *   public: boolean
     * }>}
     */
    this._routes = [];
  }

  /**
   * Registers a route for the given HTTP method and path.
   *
   * @param {string} method - HTTP verb (case-insensitive, stored uppercase)
   * @param {string} path - Route path, may contain `:param` or `*`
   * @param {Function} handler - Async function (req, res) => void
   * @param {boolean} [isPublic=false] - Whether the route is public (no encryption)
   * @returns {this} Current router instance for chaining
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
   * Attempts to match a request against registered routes.
   *
   * @param {string} method - HTTP verb (GET, POST, etc.)
   * @param {string} pathname - Request path (e.g., `/users/42`)
   * @returns {{
   *   handler: Function,
   *   params: Record<string, string>,
   *   public: boolean
   * } | null} Matched route data or null if no match
   */
  match(method, pathname) {
    for (const route of this._routes) {
      // Skip if method doesn't match
      if (route.method !== method.toUpperCase()) continue;

      const match = pathname.match(route.regex);
      if (!match) continue;

      // Build params object from capture groups
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

// Attach convenience methods: router.get(), router.post(), etc.
METHODS.forEach((verb) => {
  Router.prototype[verb.toLowerCase()] = function (path, handler) {
    return this.on(verb, path, handler, false);
  };
});

module.exports = { Router };
