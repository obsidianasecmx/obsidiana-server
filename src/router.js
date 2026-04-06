"use strict";

/**
 * Obsidiana Router — HTTP route matching and parameter extraction.
 *
 * A lightweight router that supports path parameters (`:param`) and a
 * trailing wildcard (`*`).
 *
 * @module router
 * @private
 */

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];

/**
 * Compiles a route path string into a regular expression and a list of
 * parameter names.
 *
 * @param {string} path - Route path with optional parameters
 * @returns {{ regex: RegExp, paramNames: string[] }} Compiled regex and param names
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
 * HTTP router with parameter extraction and method-based routing.
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

METHODS.forEach((verb) => {
  Router.prototype[verb.toLowerCase()] = function (path, handler) {
    return this.on(verb, path, handler, false);
  };
});

module.exports = { Router };
