"use strict";

/**
 * Obsidiana Middleware Pipeline — Sequential middleware execution.
 *
 * Manages a stack of middleware functions that process requests and responses
 * in order. Each middleware receives `(req, res, next)` and must call `next()`
 * to pass control to the next middleware. Asynchronous middleware can return
 * a Promise or use `async/await`.
 *
 * @module middleware
 * @private
 */

/**
 * Manages a sequential middleware pipeline.
 *
 * Middleware functions are executed in the order they are registered.
 * Each middleware can:
 * - Modify `req` and `res` objects
 * - End the response early by not calling `next()`
 * - Pass an error to `next(err)` to trigger rejection
 *
 * @example
 * const pipeline = new MiddlewarePipeline();
 *
 * pipeline.use(async (req, res, next) => {
 *   console.log('Before');
 *   await next();
 *   console.log('After');
 * });
 *
 * pipeline.use((req, res, next) => {
 *   res.setHeader('X-Custom', 'value');
 *   next();
 * });
 *
 * await pipeline.run(req, res);
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
   * Multiple functions are prepended in the order they are passed,
   * so the first argument runs before the second.
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
    // Reverse so that the first argument ends up at index 0 after unshifting
    for (let i = fns.length - 1; i >= 0; i--) {
      this._stack.unshift(fns[i]);
    }
    return this;
  }

  /**
   * Runs the middleware stack in order against the request and response.
   *
   * The pipeline executes each middleware sequentially. If a middleware
   * calls `next(err)`, the pipeline rejects with that error. If a middleware
   * throws or returns a rejected Promise, the pipeline rejects immediately.
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
          // If the middleware returns a Promise, forward rejection
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
