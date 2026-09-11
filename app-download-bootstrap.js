// Registers the secure app-download route without rewriting the large server.js file.
const http = require('http');

const originalCreateServer = http.createServer;
const originalListen = http.Server.prototype.listen;

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
      require('./app-download').installAppDownloadRoute(this.__bithashExpressApp);
      this.__bithashDownloadInstalled = true;
    }
    return originalListen.apply(this, args);
  };
}
