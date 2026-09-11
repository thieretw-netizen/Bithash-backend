// Registers the secure app-download route before Express fallback/error middleware can answer 404s.
// This is preloaded with Node's -r flag from package.json.
const http = require('http');

const originalCreateServer = http.createServer;
const originalListen = http.Server.prototype.listen;

function moveDownloadRouteToFront(app) {
  const stack = app && app._router && Array.isArray(app._router.stack)
    ? app._router.stack
    : null;

  if (!stack) return;

  const indexes = [];
  for (let i = 0; i < stack.length; i += 1) {
    const layer = stack[i];
    if (layer && layer.route && layer.route.path === '/api/app-download') {
      indexes.push(i);
    }
  }

  // installAppDownloadRoute adds the route at the end of the router stack.
  // Move it to the front so an existing catch-all 404/error middleware cannot
  // intercept /api/app-download before the route gets a chance to run.
  for (let i = indexes.length - 1; i >= 0; i -= 1) {
    const index = indexes[i];
    const [layer] = stack.splice(index, 1);
    stack.unshift(layer);
  }
}

if (!http.__bithashDownloadBootstrap) {
  http.__bithashDownloadBootstrap = true;

  http.createServer = function createServerWithBitHashRoute(requestListener, ...args) {
    const server = originalCreateServer.call(this, requestListener, ...args);
    if (typeof requestListener === 'function') {
      server.__bithashExpressApp = requestListener;
    }
    return server;
  };

  http.Server.prototype.listen = function listenWithBitHashRoute(...args) {
    if (this.__bithashExpressApp && !this.__bithashDownloadInstalled) {
      const app = this.__bithashExpressApp;
      require('./app-download').installAppDownloadRoute(app);
      moveDownloadRouteToFront(app);
      this.__bithashDownloadInstalled = true;
      console.log('✓ BitHash app-download route installed before fallback middleware');
    }
    return originalListen.apply(this, args);
  };
}
