const crypto = require('crypto');
const { S3Client, GetObjectCommand } = require('@aws-sdk/client-s3');

const DOWNLOADS = Object.freeze({
  windows: ['BitHash-Capital-windows.exe', 'application/vnd.microsoft.portable-executable'],
  macos: ['BitHash-Capital-macos.dmg', 'application/x-apple-disk-image']
});
const VERSION_KEY = 'apps/latest/version.json';
const TTL_SECONDS = 300;

function encode(value) {
  return encodeURIComponent(value).replace(/[!'()*]/g, char => `%${char.charCodeAt(0).toString(16).toUpperCase()}`);
}
function hmac(key, value, encoding) { return crypto.createHmac('sha256', key).update(value).digest(encoding); }
function sha256(value) { return crypto.createHash('sha256').update(value).digest('hex'); }
function buildPresignedUrl({ accountId, bucket, key, accessKeyId, secretAccessKey, expiresIn }) {
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
  const canonicalQueryString = Object.keys(params).sort().map(name => `${encode(name)}=${encode(params[name])}`).join('&');
  const canonicalRequest = ['GET', canonicalUri, canonicalQueryString, 'host:' + host + '\n', 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, credentialScope, sha256(canonicalRequest)].join('\n');
  const kDate = hmac(`AWS4${secretAccessKey}`, dateStamp);
  const kRegion = hmac(kDate, 'auto');
  const kService = hmac(kRegion, 's3');
  const kSigning = hmac(kService, 'aws4_request');
  return `https://${host}${canonicalUri}?${canonicalQueryString}&X-Amz-Signature=${hmac(kSigning, stringToSign, 'hex')}`;
}

function installAppUpdateRoute(app) {
  if (!app || app.__bithashAppUpdateRouteInstalled) return;
  app.__bithashAppUpdateRouteInstalled = true;
  app.get('/api/app-update', async (_req, res) => {
    const { R2_ACCOUNT_ID, R2_BUCKET_NAME, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY } = process.env;
    if (!R2_ACCOUNT_ID || !R2_BUCKET_NAME || !R2_ACCESS_KEY_ID || !R2_SECRET_ACCESS_KEY) {
      return res.status(503).json({ error: 'Desktop updates are temporarily unavailable' });
    }
    let manifest;
    try {
      const client = new S3Client({
        region: 'auto',
        endpoint: `https://${R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
        credentials: { accessKeyId: R2_ACCESS_KEY_ID, secretAccessKey: R2_SECRET_ACCESS_KEY }
      });
      const result = await client.send(new GetObjectCommand({ Bucket: R2_BUCKET_NAME, Key: VERSION_KEY }));
      manifest = JSON.parse(await result.Body.transformToString());
    } catch (error) {
      console.error('Desktop update manifest unavailable:', error.message);
      return res.status(503).json({ error: 'Desktop update manifest is unavailable' });
    }
    if (!manifest || typeof manifest.version !== 'string') return res.status(503).json({ error: 'Invalid desktop update manifest' });
    const base = { version: manifest.version, downloads: {} };
    for (const [platform, [file]] of Object.entries(DOWNLOADS)) {
      base.downloads[platform] = buildPresignedUrl({
        accountId: R2_ACCOUNT_ID,
        bucket: R2_BUCKET_NAME,
        key: `apps/latest/${file}`,
        accessKeyId: R2_ACCESS_KEY_ID,
        secretAccessKey: R2_SECRET_ACCESS_KEY,
        expiresIn: TTL_SECONDS
      });
    }
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    return res.json(base);
  });
}

module.exports = { installAppUpdateRoute };
