"use strict";

/**
 * Sequential middleware pipeline.
 *
 * Manages a stack of middleware functions that process requests and responses
 * in order. Each middleware receives `(req, res, next)` and must call `next()`
 * to pass control to the next middleware. Asynchronous middleware can return
 * a Promise or be declared `async`.
 *
 * @module middleware
 * @private
 */

/**
 * Pipeline that executes middleware functions sequentially.
 *
 * @example
 * const pipeline = new MiddlewarePipeline();
 * pipeline.use(async (req, res, next) => {
 *   console.log('before');
 *   await next();
 *   console.log('after');
 * });
 * await pipeline.run(req, res);
 */
class MiddlewarePipeline {
  constructor() {
    /** @private {Function[]} */
    this._stack = [];
  }

  /**
   * Appends one or more middleware functions.
   *
   * @param {...Function} fns - Middleware functions (req, res, next) => void
   * @returns {this} This pipeline for chaining
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
   * Prepends one or more middleware functions.
   *
   * The first function will run before the second, etc.
   *
   * @param {...Function} fns - Middleware functions
   * @returns {this} This pipeline for chaining
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
   * Executes the middleware stack.
   *
   * @param {object} req - Request object (mutated)
   * @param {object} res - Response object (mutated)
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
