// Registers secure desktop download/update routes before Express fallback/error middleware can answer 404s.
const http = require('http');

const originalCreateServer = http.createServer;
const originalListen = http.Server.prototype.listen;

function moveRoutesToFront(app) {
  const stack = app && app._router && Array.isArray(app._router.stack) ? app._router.stack : null;
  if (!stack) return;
  const indexes = [];
  const protectedPaths = new Set([
    '/api/app-download',
    '/api/app-update',
    '/api/apps/download/windows',
    '/api/apps/download/macos'
  ]);
  for (let i = 0; i < stack.length; i += 1) {
    const layer = stack[i];
    if (layer && layer.route && protectedPaths.has(layer.route.path)) indexes.push(i);
  }
  for (let i = indexes.length - 1; i >= 0; i -= 1) {
    const [layer] = stack.splice(indexes[i], 1);
    stack.unshift(layer);
  }
}

if (!http.__bithashDownloadBootstrap) {
  http.__bithashDownloadBootstrap = true;
  http.createServer = function createServerWithBitHashRoutes(requestListener, ...args) {
    const server = originalCreateServer.call(this, requestListener, ...args);
    if (typeof requestListener === 'function') server.__bithashExpressApp = requestListener;
    return server;
  };
  http.Server.prototype.listen = function listenWithBitHashRoutes(...args) {
    if (this.__bithashExpressApp && !this.__bithashRoutesInstalled) {
      const app = this.__bithashExpressApp;
      require('./app-download').installAppDownloadRoute(app);
      require('./app-update').installAppUpdateRoute(app);
      moveRoutesToFront(app);
      this.__bithashRoutesInstalled = true;
      console.log('✓ BitHash desktop download/update routes installed before fallback middleware');
    }
    return originalListen.apply(this, args);
  };
}
