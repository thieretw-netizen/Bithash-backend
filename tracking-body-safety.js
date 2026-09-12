// Defensive compatibility shim for tracking requests.
// Express does not populate req.body for requests without a parsed JSON body.
// The tracking endpoint expects an object with an events array, so normalize
// missing bodies before the application routes execute.

const express = require('express');

const originalJson = express.json;

express.json = function bithashSafeJsonParser(...args) {
  const parser = originalJson.apply(this, args);

  return function bithashSafeJsonMiddleware(req, res, next) {
    parser(req, res, (error) => {
      if (error) return next(error);

      if (!req.body || typeof req.body !== 'object' || Array.isArray(req.body)) {
        req.body = { events: [] };
      } else if (!Array.isArray(req.body.events)) {
        req.body.events = [];
      }

      next();
    });
  };
};
