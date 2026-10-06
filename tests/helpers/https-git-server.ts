/**
 * Local HTTPS git server for integration tests.
 *
 * Serves bare repositories under `projectRoot` through `git http-backend`
 * (CGI) behind a Node HTTPS server with a throwaway self-signed certificate
 * and HTTP Basic auth. Every request is recorded so tests can assert which
 * credentials git actually sent.
 */

import { execFileSync, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import * as https from 'node:https';
import type { AddressInfo } from 'node:net';
import * as path from 'node:path';

export interface RecordedRequest {
  method: string;
  url: string;
  authorized: boolean;
  /** Decoded `user:password` from the Basic auth header, if any */
  basicAuth?: string;
}

export interface HttpsGitServer {
  /** e.g. `https://localhost:54321` */
  origin: string;
  /** `localhost:54321` */
  host: string;
  /** Path to the self-signed CA/cert (for GIT_SSL_CAINFO) */
  certPath: string;
  requests: RecordedRequest[];
  /**
   * Called for each authorized request before it is served. May return a
   * promise to delay the response.
   */
  onAuthorizedRequest?: (req: RecordedRequest) => void | Promise<void>;
  close(): Promise<void>;
}

/** Returns true if openssl and git-http-backend are available. */
export function canRunHttpsGitServer(): boolean {
  try {
    execFileSync('openssl', ['version'], { stdio: 'ignore' });
    const execPath = execFileSync('git', ['--exec-path'], {
      encoding: 'utf8',
    }).trim();
    return fs.existsSync(path.join(execPath, 'git-http-backend'));
  } catch {
    return false;
  }
}

export async function startHttpsGitServer(options: {
  projectRoot: string;
  workDir: string;
  /** Accepted Basic auth user:password */
  credentials: string;
}): Promise<HttpsGitServer> {
  const keyPath = path.join(options.workDir, 'server-key.pem');
  const certPath = path.join(options.workDir, 'server-cert.pem');
  execFileSync(
    'openssl',
    [
      'req',
      '-x509',
      '-newkey',
      'rsa:2048',
      '-nodes',
      '-keyout',
      keyPath,
      '-out',
      certPath,
      '-days',
      '1',
      '-subj',
      '/CN=localhost',
      '-addext',
      'subjectAltName=DNS:localhost,IP:127.0.0.1',
    ],
    { stdio: 'ignore' }
  );

  const backend = path.join(
    execFileSync('git', ['--exec-path'], { encoding: 'utf8' }).trim(),
    'git-http-backend'
  );

  const server: HttpsGitServer = {
    origin: '',
    host: '',
    certPath,
    requests: [],
    close: async () => undefined,
  };

  const httpsServer = https.createServer(
    {
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath),
    },
    async (req, res) => {
      const header = req.headers.authorization ?? '';
      const basicAuth = header.startsWith('Basic ')
        ? Buffer.from(header.slice(6), 'base64').toString('utf8')
        : undefined;
      const record: RecordedRequest = {
        method: req.method ?? 'GET',
        url: req.url ?? '/',
        authorized: basicAuth === options.credentials,
        basicAuth,
      };
      server.requests.push(record);

      if (!record.authorized) {
        res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="test"' });
        res.end('Unauthorized');
        return;
      }

      try {
        await server.onAuthorizedRequest?.(record);
      } catch {
        // ignore test hook errors
      }

      const url = new URL(req.url ?? '/', 'https://localhost');
      const env: NodeJS.ProcessEnv = {
        PATH: process.env.PATH,
        GIT_PROJECT_ROOT: options.projectRoot,
        GIT_HTTP_EXPORT_ALL: '1',
        REQUEST_METHOD: req.method,
        PATH_INFO: decodeURIComponent(url.pathname),
        QUERY_STRING: url.search.replace(/^\?/, ''),
        CONTENT_TYPE: req.headers['content-type'] ?? '',
        REMOTE_USER: 'x-access-token',
        REMOTE_ADDR: '127.0.0.1',
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: '/dev/null',
      };
      if (req.headers['content-encoding']) {
        env.HTTP_CONTENT_ENCODING = String(req.headers['content-encoding']);
      }
      if (req.headers['git-protocol']) {
        env.GIT_PROTOCOL = String(req.headers['git-protocol']);
      }

      const cgi = spawn(backend, [], { env });
      req.pipe(cgi.stdin);

      let buffer = Buffer.alloc(0);
      let headersSent = false;
      cgi.stdout.on('data', (chunk: Buffer) => {
        if (headersSent) {
          res.write(chunk);
          return;
        }
        buffer = Buffer.concat([buffer, chunk]);
        const sep = buffer.indexOf('\r\n\r\n');
        if (sep === -1) return;
        const headerText = buffer.subarray(0, sep).toString('utf8');
        const body = buffer.subarray(sep + 4);
        let status = 200;
        const headers: Record<string, string> = {};
        for (const line of headerText.split('\r\n')) {
          const idx = line.indexOf(':');
          if (idx === -1) continue;
          const name = line.slice(0, idx).trim();
          const value = line.slice(idx + 1).trim();
          if (name.toLowerCase() === 'status') {
            status = Number.parseInt(value, 10);
          } else {
            headers[name] = value;
          }
        }
        res.writeHead(status, headers);
        headersSent = true;
        if (body.length) res.write(body);
      });
      cgi.on('close', () => {
        if (!headersSent) {
          res.writeHead(500);
        }
        res.end();
      });
    }
  );

  await new Promise<void>((resolve) =>
    httpsServer.listen(0, '127.0.0.1', resolve)
  );
  const { port } = httpsServer.address() as AddressInfo;
  server.host = `localhost:${port}`;
  server.origin = `https://${server.host}`;
  server.close = () =>
    new Promise<void>((resolve) => {
      httpsServer.closeAllConnections?.();
      httpsServer.close(() => resolve());
    });
  return server;
}
