"use strict";

/**
 * Obsidiana Middleware Pipeline — Sequential middleware execution.
 *
 * Manages a stack of middleware functions that process requests and responses
 * in order. Each middleware receives `(req, res, next)` and must call `next()`
 * to pass control to the next middleware.
 *
 * @module middleware
 * @private
 */

/**
 * Manages a sequential middleware pipeline.
 */
class MiddlewarePipeline {
  constructor() {
    /**
     * Internal middleware stack.
     * @private
     * @type {Function[]}
     */
    this._stack = [];
  }

  /**
   * Registers one or more middleware functions at the end of the stack.
   *
   * @param {...Function} fns - Middleware functions (req, res, next) => void
   * @returns {this} Current pipeline instance for chaining
   * @throws {TypeError} If any argument is not a function
   */
  use(...fns) {
    for (const fn of fns) {
      if (typeof fn !== "function") {
        throw new TypeError(`Middleware must be a function, got ${typeof fn}`);
      }
      this._stack.push(fn);
    }
    return this;
  }

  /**
   * Registers one or more middleware functions at the front of the stack.
   *
   * @param {...Function} fns - Middleware functions (req, res, next) => void
   * @returns {this} Current pipeline instance for chaining
   * @throws {TypeError} If any argument is not a function
   */
  prepend(...fns) {
    for (const fn of fns) {
      if (typeof fn !== "function") {
        throw new TypeError(`Middleware must be a function, got ${typeof fn}`);
      }
    }
    for (let i = fns.length - 1; i >= 0; i--) {
      this._stack.unshift(fns[i]);
    }
    return this;
  }

  /**
   * Runs the middleware stack in order against the request and response.
   *
   * @param {object} req - Request object (will be mutated by middleware)
   * @param {object} res - Response object (will be mutated by middleware)
   * @returns {Promise<void>} Resolves when all middleware have completed
   */
  run(req, res) {
    const stack = this._stack;
    let index = 0;

    return new Promise((resolve, reject) => {
      function next(err) {
        if (err) return reject(err);
        if (index >= stack.length) return resolve();

        const fn = stack[index++];
        try {
          const result = fn(req, res, next);
          if (result && typeof result.then === "function") {
            result.then(undefined, reject);
          }
        } catch (e) {
          reject(e);
        }
      }

      next();
    });
  }
}

module.exports = { MiddlewarePipeline };
