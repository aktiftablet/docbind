/** In-process HTTP transport: real IncomingMessage/ServerResponse and middleware,
 * without binding a port. Multipart bodies pass through Multer unchanged. */
import { IncomingMessage, ServerResponse } from 'node:http';
import { Duplex } from 'node:stream';
import { strict as assert } from 'node:assert';
import type { Express } from 'express';

interface Result { status: number; body: any; text: string; headers: Record<string, unknown> }
class TestRequest implements PromiseLike<Result> {
  private headers: Record<string, string> = {};
  private data: unknown;
  private parts: Buffer[] = [];
  private boundary = 'docbind-test-boundary-389472';
  private expected?: number;
  constructor(private app: Express, private method: string, private path: string) {}
  set(name: string | Record<string, string>, value?: string): this {
    if (typeof name === 'object') { for (const [k, v] of Object.entries(name)) this.headers[k.toLowerCase()] = v; }
    else this.headers[name.toLowerCase()] = value!;
    return this;
  }
  auth(token: string, _options: { type: 'bearer' }): this { return this.set('authorization', `Bearer ${token}`); }
  send(body: unknown): this { this.data = body; return this; }
  field(name: string, value: string): this {
    this.parts.push(Buffer.from(`--${this.boundary}\r\nContent-Disposition: form-data; name="${name}"\r\n\r\n${value}\r\n`));
    return this;
  }
  attach(name: string, content: Buffer, filename: string): this {
    this.parts.push(Buffer.from(`--${this.boundary}\r\nContent-Disposition: form-data; name="${name}"; filename="${filename}"\r\nContent-Type: application/octet-stream\r\n\r\n`), content, Buffer.from('\r\n'));
    return this;
  }
  expect(status: number): this { this.expected = status; return this; }
  then<T = Result, E = never>(resolve?: ((result: Result) => T | PromiseLike<T>) | null, reject?: ((reason: unknown) => E | PromiseLike<E>) | null): PromiseLike<T | E> {
    return this.run().then(resolve, reject);
  }
  private async run(): Promise<Result> {
    let body = Buffer.alloc(0);
    if (this.parts.length) {
      body = Buffer.concat([...this.parts, Buffer.from(`--${this.boundary}--\r\n`)]);
      this.headers['content-type'] = `multipart/form-data; boundary=${this.boundary}`;
    } else if (this.data !== undefined) {
      if (typeof this.data === 'string') body = Buffer.from(this.data);
      else { body = Buffer.from(JSON.stringify(this.data)); this.headers['content-type'] ??= 'application/json'; }
    }
    this.headers['content-length'] = String(body.length);
    this.headers.host = 'localhost';
    const socket = new Duplex({ read() {}, write(_chunk, _encoding, cb) { cb(); } });
    Object.defineProperty(socket, 'remoteAddress', { value: '127.0.0.1' });
    const req = new IncomingMessage(socket as any);
    req.method = this.method; req.url = this.path; req.headers = this.headers;
    req.httpVersion = '1.1'; req.httpVersionMajor = 1; req.httpVersionMinor = 1;
    const res = new ServerResponse(req);
    res.assignSocket(socket as any);
    const chunks: Buffer[] = [];
    const originalWrite = res.write.bind(res), originalEnd = res.end.bind(res);
    res.write = ((chunk: any, ...args: any[]) => {
      chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, typeof args[0] === 'string' ? args[0] : undefined));
      return (originalWrite as any)(chunk, ...args);
    }) as any;
    res.end = ((chunk?: any, ...args: any[]) => {
      if (chunk && typeof chunk !== 'function') chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
      return (originalEnd as any)(chunk, ...args);
    }) as any;
    const complete = new Promise<Result>((resolve, reject) => {
      res.once('error', reject); req.once('error', reject);
      res.once('finish', () => {
        const text = Buffer.concat(chunks).toString();
        let parsed: any; try { parsed = JSON.parse(text); } catch { parsed = {}; }
        resolve({ status: res.statusCode, body: parsed, text, headers: res.getHeaders() });
      });
    });
    req.complete = true;
    req.push(body); req.push(null);
    this.app(req, res);
    const result = await complete;
    if (this.expected !== undefined) assert.equal(result.status, this.expected, `${this.method} ${this.path}: ${result.text}`);
    return result;
  }
}
export default function request(app: Express) {
  return { post: (path: string) => new TestRequest(app, 'POST', path), get: (path: string) => new TestRequest(app, 'GET', path) };
}
