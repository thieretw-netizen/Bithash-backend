// Defensive compatibility shim for tracking requests.
// Express does not populate req.body for requests without a parsed JSON body.
// The tracking endpoint expects an object with an events array, so normalize
// missing bodies before the application routes execute.

const express = require('express');
const http = require('http');

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

// Some tracker clients can send an empty POST (no body at all).  The legacy
// tracker handler assumes req.body exists and throws before Express can reply.
// Stop only those malformed/empty tracking requests; valid tracking payloads
// continue through the normal application route unchanged.
if (!http.__bithashTrackingGuard) {
  http.__bithashTrackingGuard = true;
  const originalCreateServer = http.createServer;

  http.createServer = function bithashTrackingSafeServer(requestListener, ...args) {
    if (typeof requestListener !== 'function') {
      return originalCreateServer.call(this, requestListener, ...args);
    }

    const guardedListener = function bithashTrackingGuardedListener(req, res) {
      const method = String(req.method || '').toUpperCase();
      const url = String(req.url || '').split('?')[0].toLowerCase();
      const lengthHeader = req.headers && req.headers['content-length'];
      const contentLength = lengthHeader == null ? null : Number(lengthHeader);
      const isEmptyBody = contentLength === 0 || (contentLength == null && !req.headers['transfer-encoding']);
      const isTrackingRequest = /track|tracking/.test(url);

      if (method === 'POST' && isTrackingRequest && isEmptyBody) {
        res.statusCode = 200;
        res.setHeader('Content-Type', 'application/json; charset=utf-8');
        res.end(JSON.stringify({ success: true, processed: 0 }));
        return;
      }

      return requestListener(req, res);
    };

    return originalCreateServer.call(this, guardedListener, ...args);
  };
}
