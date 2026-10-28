'use strict';
// Matter's optional localhost-only web proxy. No npm dependencies required (Node.js 18+).
const http = require('node:http');
const dns = require('node:dns').promises;
const net = require('node:net');
const { URL } = require('node:url');
const { Readable } = require('node:stream');
const HOST = '127.0.0.1';
const PORT = Number(process.env.MATTER_PROXY_PORT || 4317);
const PREFIX = '/_matter_proxy/';
const MAX_BYTES = 12 * 1024 * 1024;
const TIMEOUT_MS = 18000;

function isPrivateIPv4(ip) {
  const p = ip.split('.').map(Number);
  if (p.length !== 4 || p.some(n => !Number.isInteger(n) || n < 0 || n > 255)) return true;
  return p[0] === 0 || p[0] === 10 || p[0] === 127 || p[0] >= 224 ||
    (p[0] === 169 && p[1] === 254) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) || (p[0] === 100 && p[1] >= 64 && p[1] <= 127) ||
    (p[0] === 198 && (p[1] === 18 || p[1] === 19));
}
function isPrivateIPv6(ip) {
  const x = ip.toLowerCase().split('%')[0];
  return x === '::' || x === '::1' || x.startsWith('fc') || x.startsWith('fd') ||
    /^fe[89ab]/.test(x) || x.startsWith('ff') || x.startsWith('2001:db8:') ||
    x.startsWith('::ffff:') || x.startsWith('2001:') && !x.startsWith('2001:4860:');
}
function isPrivateIP(ip) { return net.isIP(ip) === 4 ? isPrivateIPv4(ip) : net.isIP(ip) === 6 ? isPrivateIPv6(ip) : true; }
async function validatePublicTarget(target) {
  let u;
  try { u = new URL(target); } catch { throw new Error('Invalid destination URL.'); }
  if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only HTTP and HTTPS websites are supported.');
  if (u.username || u.password) throw new Error('URLs containing usernames or passwords are not supported.');
  const host = u.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!host || host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.local') || host.endsWith('.internal')) throw new Error('Local and private destinations are blocked for safety.');
  if (net.isIP(host)) {
    if (isPrivateIP(host)) throw new Error('Private IP addresses are blocked for safety.');
  } else {
    let records;
    try { records = await dns.lookup(host, { all: true, verbatim: true }); }
    catch { throw new Error('Could not resolve this website. Check the address or your connection.'); }
    if (!records.length || records.some(r => isPrivateIP(r.address))) throw new Error('This domain resolves to a private or restricted address and was blocked.');
  }
  return u;
}
function proxyPath(target) {
  const u = new URL(target);
  return PREFIX + u.protocol.slice(0, -1) + '/' + u.host + u.pathname + u.search + u.hash;
}
function absoluteResource(value, base) {
  const v = String(value || '').trim();
  if (!v || /^(data:|blob:|javascript:|mailto:|tel:|about:|#)/i.test(v)) return value;
  try {
    const resolved = new URL(v, base);
    if (!['http:', 'https:'].includes(resolved.protocol)) return value;
    return proxyPath(resolved.href);
  } catch { return value; }
}
function rewriteCss(css, targetUrl) {
  return css.replace(/url\(\s*(['"]?)(.*?)\1\s*\)/gi, (whole, quote, value) => {
    if (!value || /^(data:|blob:|#)/i.test(value.trim())) return whole;
    return `url("${absoluteResource(value, targetUrl)}")`;
  }).replace(/@import\s+(['"])(.*?)\1/gi, (whole, quote, value) => `@import "${absoluteResource(value, targetUrl)}"`);
}
function rewriteHtml(html, targetUrl) {
  const baseProxy = proxyPath(targetUrl);
  // Remove any existing base tag; insert ours so relative paths continue through the proxy.
  html = html.replace(/<base\b[^>]*>/gi, '');
  html = html.replace(/\s(?:http-equiv\s*=\s*(['"])content-security-policy\1|integrity\s*=\s*(['"])[^'"]*\2)/gi, '');
  // Rewrite common URL-bearing attributes. Relative links use the proxy base inserted below.
  html = html.replace(/\b(href|src|action|formaction|poster|data|xlink:href)\s*=\s*(["'])(.*?)\2/gi, (whole, attr, quote, value) => {
    const rewritten = absoluteResource(value, targetUrl);
    return `${attr}=${quote}${rewritten}${quote}`;
  });
  html = html.replace(/\bsrcset\s*=\s*(["'])(.*?)\1/gi, (whole, quote, value) => {
    const rewritten = value.split(',').map(part => {
      const bits = part.trim().split(/\s+/); bits[0] = absoluteResource(bits[0], targetUrl); return bits.join(' ');
    }).join(', ');
    return `srcset=${quote}${rewritten}${quote}`;
  });
  // Rewrite simple CSS URLs inside style blocks and inline styles.
  html = html.replace(/<style\b([^>]*)>([\s\S]*?)<\/style>/gi, (_, attrs, css) => `<style${attrs}>${rewriteCss(css, targetUrl)}</style>`);
  html = html.replace(/style\s*=\s*(["'])(.*?)\1/gi, (whole, quote, css) => `style=${quote}${rewriteCss(css, targetUrl)}${quote}`);
  const baseTag = `<base href="${baseProxy.replace(/&/g, '&amp;').replace(/"/g, '&quot;')}">`;
  if (/<head\b[^>]*>/i.test(html)) html = html.replace(/<head\b[^>]*>/i, match => match + baseTag);
  else html = baseTag + html;
  return html;
}
function send(res, status, body, type = 'text/plain; charset=utf-8') {
  res.writeHead(status, { 'Content-Type': type, 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Access-Control-Allow-Origin': '*' });
  res.end(body);
}
function parseProxyRequest(reqUrl) {
  const incoming = new URL(reqUrl, `http://${HOST}:${PORT}`);
  if (!incoming.pathname.startsWith(PREFIX)) return null;
  const tail = incoming.pathname.slice(PREFIX.length);
  const m = tail.match(/^(https?)\/([^/]+)(\/.*)?$/i);
  if (!m) throw new Error('Malformed proxy address.');
  const scheme = m[1].toLowerCase();
  const host = m[2];
  const path = m[3] || '/';
  return `${scheme}://${host}${path}${incoming.search}`;
}
async function fetchTarget(initialUrl, req) {
  let target = initialUrl;
  for (let hops = 0; hops <= 5; hops++) {
    await validatePublicTarget(target);
    const headers = {
      'User-Agent': 'Mozilla/5.0 (compatible; MatterLocalProxy/1.0)',
      'Accept': req.headers.accept || '*/*',
      'Accept-Language': req.headers['accept-language'] || 'en-US,en;q=0.8',
    };
    if (req.headers.range) headers.Range = req.headers.range;
    const method = ['GET', 'HEAD', 'POST'].includes(req.method) ? req.method : 'GET';
    let body;
    if (method === 'POST') {
      const chunks = [];
      for await (const chunk of req) { chunks.push(chunk); if (chunks.reduce((n, c) => n + c.length, 0) > 1024 * 1024) throw new Error('Request body too large.'); }
      body = Buffer.concat(chunks);
      if (req.headers['content-type']) headers['Content-Type'] = req.headers['content-type'];
    }
    const response = await fetch(target, { method, headers, body, redirect: 'manual', signal: AbortSignal.timeout(TIMEOUT_MS) });
    if ([301, 302, 303, 307, 308].includes(response.status) && response.headers.get('location')) {
      if (hops === 5) throw new Error('Too many redirects.');
      target = new URL(response.headers.get('location'), target).href;
      continue;
    }
    return { response, target, method };
  }
  throw new Error('Too many redirects.');
}
const server = http.createServer(async (req, res) => {
  if (req.url === '/api/status') return send(res, 200, JSON.stringify({ ok: true, name: 'Matter Local Proxy', port: PORT, safety: 'loopback-only; private destinations blocked' }), 'application/json; charset=utf-8');
  if (req.url === '/favicon.ico') { res.writeHead(204); return res.end(); }
  if (!req.url.startsWith(PREFIX)) return send(res, 200, `Matter Local Proxy is running on http://${HOST}:${PORT}\n\nOpen matter.html in your browser and turn Proxy ON.\n`, 'text/plain; charset=utf-8');
  try {
    const targetUrl = parseProxyRequest(req.url);
    if (!targetUrl) return send(res, 400, 'Bad proxy URL.');
    const { response, target, method } = await fetchTarget(targetUrl, req);
    const contentType = response.headers.get('content-type') || 'application/octet-stream';
    const status = response.status;
    const headers = {
      'Content-Type': contentType,
      'Cache-Control': 'no-store',
      'X-Content-Type-Options': 'nosniff',
      // Deliberately do not forward frame-denial, CSP, Set-Cookie, or origin policy headers.
    };
    if (response.headers.get('content-range')) headers['Content-Range'] = response.headers.get('content-range');
    if (response.headers.get('accept-ranges')) headers['Accept-Ranges'] = response.headers.get('accept-ranges');
    res.writeHead(status, headers);
    if (method === 'HEAD' || status === 204 || status === 304) return res.end();
    if (!/text\/html|text\/css/i.test(contentType)) {
      // Stream images, fonts, downloads, and other binary responses instead of buffering them.
      if (response.body) Readable.fromWeb(response.body).pipe(res); else res.end();
      return;
    }
    const chunks = []; let total = 0;
    for await (const chunk of response.body) {
      total += chunk.length;
      if (total > MAX_BYTES) { res.end('Matter proxy: page is too large to rewrite. Open it in a regular browser tab.'); return; }
      chunks.push(Buffer.from(chunk));
    }
    const bytes = Buffer.concat(chunks);
    if (/text\/html/i.test(contentType)) res.end(rewriteHtml(bytes.toString('utf8'), target));
    else res.end(rewriteCss(bytes.toString('utf8'), target));
  } catch (err) {
    if (!res.headersSent) send(res, 502, `Matter local proxy error: ${err.message}\n\nTry another site or use Matter's Full browser button.`, 'text/plain; charset=utf-8');
    else res.end();
  }
});
server.on('clientError', (_err, socket) => { try { socket.end('HTTP/1.1 400 Bad Request\r\n\r\n'); } catch {} });
server.listen(PORT, HOST, () => {
  console.log(`Matter Local Proxy running at http://${HOST}:${PORT}`);
  console.log('Keep this terminal open while using Matter. Press Ctrl+C to stop.');
  console.log('Security: bound to localhost; local/private network destinations are blocked.');
});
