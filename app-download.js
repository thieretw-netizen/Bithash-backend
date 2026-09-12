const crypto = require('crypto');

const FILES = Object.freeze({
  'BitHash-Capital-windows.exe': 'application/vnd.microsoft.portable-executable',
  'BitHash-Capital-macos.dmg': 'application/x-apple-diskimage'
});

const DOWNLOAD_PREFIX = 'apps/latest/';
const DOWNLOAD_TTL_SECONDS = 300;

function encode(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, (char) =>
    `%${char.charCodeAt(0).toString(16).toUpperCase()}`
  );
}

function hmac(key, value, encoding) {
  return crypto.createHmac('sha256', key).update(value).digest(encoding);
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('hex');
}

function detectPlatform(req) {
  const headers = req?.headers || {};
  const userAgent = String(headers['user-agent'] || headers['User-Agent'] || '');
  const clientHints = String(headers['sec-ch-ua-platform'] || headers['Sec-CH-UA-Platform'] || '').replace(/[\"]/g, '');
  const value = `${userAgent} ${clientHints}`;
  if (/Windows NT|Windows Phone/i.test(value)) return 'windows';
  if (/iPhone|iPad|iPod/i.test(value)) return 'ios';
  if (/Android/i.test(value)) return 'android';
  if (/Macintosh|Mac OS X/i.test(value)) return 'macos';
  return 'other';
}

function requiredPlatformForFile(file) {
  if (file === 'BitHash-Capital-windows.exe') return 'windows';
  if (file === 'BitHash-Capital-macos.dmg') return 'macos';
  return null;
}

function platformRequirements(platform) {
  if (platform === 'windows') return 'Windows 10 (64-bit) or Windows 11 (64-bit). Windows on ARM requires Windows 10 version 1903 or later.';
  if (platform === 'macos') return 'macOS 13 Ventura or later. Universal Intel + Apple silicon build.';
  return '';
}

function buildPresignedUrl({
  accountId,
  bucket,
  key,
  accessKeyId,
  secretAccessKey,
  expiresIn
}) {
  const host = `${accountId}.r2.cloudflarestorage.com`;
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);
  const credentialScope = `${dateStamp}/auto/s3/aws4_request`;
  const canonicalUri = `/${encode(bucket)}/${key.split('/').map(encode).join('/')}`;

  const params = {
    'X-Amz-Algorithm': 'AWS4-HMAC-SHA256',
    'X-Amz-Credential': `${accessKeyId}/${credentialScope}`,
    'X-Amz-Date': amzDate,
    'X-Amz-Expires': String(expiresIn),
    'X-Amz-SignedHeaders': 'host'
  };

  const canonicalQueryString = Object.keys(params)
    .sort()
    .map((name) => `${encode(name)}=${encode(params[name])}`)
    .join('&');

  const canonicalHeaders = `host:${host}\n`;
  const signedHeaders = 'host';
  const payloadHash = 'UNSIGNED-PAYLOAD';

  const canonicalRequest = [
    'GET',
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeaders,
    payloadHash
  ].join('\n');

  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256(canonicalRequest)
  ].join('\n');

  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, 'auto');
  const kService = hmac(kRegion, 's3');
  const kSigning = hmac(kService, 'aws4_request');
  const signature = hmac(kSigning, stringToSign, 'hex');

  return `https://${host}${canonicalUri}?${canonicalQueryString}&X-Amz-Signature=${signature}`;
}

function installAppDownloadRoute(app) {
  if (!app || app.__bithashAppDownloadRouteInstalled) return;

  app.__bithashAppDownloadRouteInstalled = true;

  function handleDownload(req, res) {
    const file = typeof req.query?.file === 'string' ? req.query.file : '';
    const contentType = FILES[file];

    if (!contentType) {
      return res.status(404).json({ error: 'Download not found' });
    }

    const requiredPlatform = requiredPlatformForFile(file);
    const clientPlatform = detectPlatform(req);
    if (requiredPlatform && clientPlatform !== requiredPlatform) {
      return res.status(403).json({
        error: 'This native download is only available for the matching device platform.',
        requestedFile: file,
        detectedPlatform: clientPlatform,
        requiredPlatform,
        requirements: platformRequirements(requiredPlatform)
      });
    }

    const {
      R2_ACCOUNT_ID,
      R2_BUCKET_NAME,
      R2_ACCESS_KEY_ID,
      R2_SECRET_ACCESS_KEY
    } = process.env;

    if (
      !R2_ACCOUNT_ID ||
      !R2_BUCKET_NAME ||
      !R2_ACCESS_KEY_ID ||
      !R2_SECRET_ACCESS_KEY
    ) {
      console.error('App download R2 endpoint is not configured');
      return res.status(503).json({
        error: 'Downloads are temporarily unavailable'
      });
    }

    const key = `${DOWNLOAD_PREFIX}${file}`;

    const url = buildPresignedUrl({
      accountId: R2_ACCOUNT_ID,
      bucket: R2_BUCKET_NAME,
      key,
      accessKeyId: R2_ACCESS_KEY_ID,
      secretAccessKey: R2_SECRET_ACCESS_KEY,
      expiresIn: DOWNLOAD_TTL_SECONDS
    });

    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-BitHash-Download', 'r2-presigned');
    res.setHeader('Content-Type', contentType);
    res.setHeader('Location', url);

    return res.status(302).end();
  }

  app.get('/api/app-download', handleDownload);
  app.head('/api/app-download', handleDownload);
}

module.exports = { installAppDownloadRoute };
