import { WebSocketServer, WebSocket } from 'ws';
import http from 'http';
import { URL } from 'url';
import type { Duplex } from 'stream';
import { verifyJWT } from '../utils/jwt';

const SIGNALR_RECORD_SEPARATOR = String.fromCharCode(0x1e);
const SIGNALR_HANDSHAKE_ACK = JSON.stringify({}) + SIGNALR_RECORD_SEPARATOR;
const SIGNALR_UPDATE_TYPE_SYNC_VAULT = 5;
const SIGNALR_UPDATE_TYPE_LOG_OUT = 11;
const SIGNALR_UPDATE_TYPE_DEVICE_STATUS = 12;
const SIGNALR_UPDATE_TYPE_BACKUP_RESTORE_PROGRESS = 13;
// Mirrors the upstream Durable Object: the anonymous hub pushes approval
// responses with target "AuthRequestResponseRecieved" and update type 16.
const SIGNALR_UPDATE_TYPE_AUTH_REQUEST_RESPONSE = 16;
const ANONYMOUS_HUB_PATH = '/notifications/anonymous-hub';

type HubKind = 'user' | 'anonymous-auth-request';
type HubProtocol = 'json' | 'messagepack';

interface WsAttachment {
  kind: HubKind;
  userId: string | null;
  authRequestId: string | null;
  handshakeComplete: boolean;
  protocol: HubProtocol;
  deviceIdentifier: string | null;
}

interface HubUser {
  sockets: Set<WebSocket>;
  deviceIdentifiers: Map<WebSocket, string | null>;
}

export interface NotificationsHubOptions {
  /**
   * Deprecated: accept a raw access JWT in the `?access_token=` query string.
   * Query strings end up in proxy logs and browser history, so this is off by
   * default; clients should use the one-time `?id=` token or a Bearer header.
   */
  allowLegacyQueryToken?: boolean;
  /**
   * Validates the auth request id passed as `?Token=` on the anonymous hub.
   * The upstream handler only lets non-expired auth requests subscribe to
   * their approval response; the self-hosted hub needs the same check at
   * WebSocket-upgrade time (the fetch router is bypassed for upgrades).
   */
  validateAnonymousAuthRequest?: (authRequestId: string) => Promise<boolean>;
}

function extractAccessToken(req: http.IncomingMessage, allowQueryToken: boolean): string | null {
  if (allowQueryToken) {
    const url = new URL(req.url || '', `http://${req.headers.host || 'localhost'}`);
    const queryToken = String(url.searchParams.get('access_token') || '').trim();
    if (queryToken) return queryToken;
  }

  const authHeader = String(req.headers['authorization'] || '').trim();
  const match = authHeader.match(/^Bearer\s+(.+)$/i);
  return match?.[1]?.trim() || null;
}

function extractWsConnectionToken(req: http.IncomingMessage): string | null {
  const url = new URL(req.url || '', `http://${req.headers.host || 'localhost'}`);
  return String(url.searchParams.get('id') || '').trim() || null;
}

function extractAnonymousToken(req: http.IncomingMessage): string | null {
  const url = new URL(req.url || '', `http://${req.headers.host || 'localhost'}`);
  return String(
    url.searchParams.get('Token') || url.searchParams.get('token') || ''
  ).trim() || null;
}

// --- SignalR MessagePack hub protocol framing (mirrors the upstream Durable
// Object so native clients, which negotiate messagepack by default, receive
// the same wire format from the self-hosted hub as from Cloudflare Workers).

function concatBytes(chunks: Uint8Array[]): Uint8Array {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function encodeUtf8(value: string): Uint8Array {
  return new TextEncoder().encode(value);
}

function encodeMsgPackInteger(value: number): Uint8Array {
  const normalized = Math.trunc(value);
  if (normalized >= 0 && normalized <= 0x7f) {
    return new Uint8Array([normalized]);
  }
  if (normalized >= 0 && normalized <= 0xff) {
    return new Uint8Array([0xcc, normalized]);
  }
  if (normalized >= 0 && normalized <= 0xffff) {
    return new Uint8Array([0xcd, normalized >> 8, normalized & 0xff]);
  }
  const safe = normalized >>> 0;
  return new Uint8Array([
    0xce,
    (safe >>> 24) & 0xff,
    (safe >>> 16) & 0xff,
    (safe >>> 8) & 0xff,
    safe & 0xff,
  ]);
}

function encodeMsgPackString(value: string): Uint8Array {
  const bytes = encodeUtf8(value);
  const len = bytes.length;
  if (len < 32) {
    return concatBytes([new Uint8Array([0xa0 | len]), bytes]);
  }
  if (len <= 0xff) {
    return concatBytes([new Uint8Array([0xd9, len]), bytes]);
  }
  return concatBytes([new Uint8Array([0xda, (len >> 8) & 0xff, len & 0xff]), bytes]);
}

function encodeMsgPackTimestamp(date: Date): Uint8Array {
  const seconds = BigInt(Math.floor(date.getTime() / 1000));
  const nanos = BigInt(date.getMilliseconds()) * 1000000n;
  const timestamp = (nanos << 34n) | seconds;
  const payload = new Uint8Array(8);
  for (let i = 7; i >= 0; i--) {
    payload[i] = Number((timestamp >> BigInt((7 - i) * 8)) & 0xffn);
  }
  return concatBytes([new Uint8Array([0xc7, 0x08, 0xff]), payload]);
}

function encodeMsgPackArray(values: unknown[]): Uint8Array {
  const items = values.map(encodeMsgPack);
  const len = items.length;
  const header =
    len < 16
      ? new Uint8Array([0x90 | len])
      : new Uint8Array([0xdc, (len >> 8) & 0xff, len & 0xff]);
  return concatBytes([header, ...items]);
}

function encodeMsgPackMap(value: Record<string, unknown>): Uint8Array {
  const entries = Object.entries(value);
  const len = entries.length;
  const header =
    len < 16
      ? new Uint8Array([0x80 | len])
      : new Uint8Array([0xde, (len >> 8) & 0xff, len & 0xff]);
  const chunks: Uint8Array[] = [header];
  for (const [key, entryValue] of entries) {
    chunks.push(encodeMsgPackString(key), encodeMsgPack(entryValue));
  }
  return concatBytes(chunks);
}

function encodeMsgPack(value: unknown): Uint8Array {
  if (value === null || value === undefined) return new Uint8Array([0xc0]);
  if (value instanceof Date) return encodeMsgPackTimestamp(value);
  if (typeof value === 'string') return encodeMsgPackString(value);
  if (typeof value === 'number') return encodeMsgPackInteger(value);
  if (typeof value === 'boolean') return new Uint8Array([value ? 0xc3 : 0xc2]);
  if (Array.isArray(value)) return encodeMsgPackArray(value);
  if (value instanceof Uint8Array) {
    const len = value.length;
    if (len <= 0xff) return concatBytes([new Uint8Array([0xc4, len]), value]);
    return concatBytes([new Uint8Array([0xc5, (len >> 8) & 0xff, len & 0xff]), value]);
  }
  return encodeMsgPackMap(value as Record<string, unknown>);
}

function frameSignalRBinary(payload: Uint8Array): Uint8Array {
  const len = payload.length;
  const prefix: number[] = [];
  let value = len;
  do {
    let current = value & 0x7f;
    value >>>= 7;
    if (value > 0) current |= 0x80;
    prefix.push(current);
  } while (value > 0);
  return concatBytes([new Uint8Array(prefix), payload]);
}

function buildSignalRJsonInvocation(
  updateType: number,
  payload: Record<string, unknown>,
  contextId: string | null,
  target: string = 'ReceiveMessage'
): string {
  return (
    JSON.stringify({
      type: 1,
      target,
      arguments: [
        {
          ContextId: contextId,
          Type: updateType,
          Payload: payload,
        },
      ],
    }) + SIGNALR_RECORD_SEPARATOR
  );
}

function buildSignalRMessagePackInvocation(
  updateType: number,
  payload: Record<string, unknown>,
  contextId: string | null,
  target: string = 'ReceiveMessage'
): Uint8Array {
  // SignalR MessagePack hub protocol uses an array-based invocation shape:
  // [type, headers, invocationId, target, arguments, streamIds]
  const encodedPayload = encodeMsgPack([
    1,
    {},
    null,
    target,
    [
      {
        ContextId: contextId,
        Type: updateType,
        Payload: payload,
      },
    ],
    [],
  ]);
  return frameSignalRBinary(encodedPayload);
}

interface WsConnectionTokenEntry {
  userId: string;
  deviceIdentifier: string | null;
  expiresAt: number;
}

export class NotificationsHubServer {
  private wss: WebSocketServer;
  private hubPath: string;
  private users: Map<string, HubUser> = new Map();
  private jwtSecret: string;
  // Short-lived websocket connection tokens (issued by /notifications/hub/negotiate,
  // consumed on ws upgrade). Mirrors the upstream Durable Object storage so the
  // self-hosted hub keeps the same signed-token security model as Cloudflare Workers.
  private wsConnectionTokens: Map<string, WsConnectionTokenEntry> = new Map();
  private wsTokenLastCleanupAt: number = 0;
  private allowLegacyQueryToken: boolean;
  private validateAnonymousAuthRequest: ((authRequestId: string) => Promise<boolean>) | undefined;

  constructor(
    server: http.Server,
    jwtSecret: string,
    path: string = '/notifications/hub',
    options: NotificationsHubOptions = {}
  ) {
    this.jwtSecret = jwtSecret;
    this.hubPath = path;
    this.allowLegacyQueryToken = options.allowLegacyQueryToken === true;
    this.validateAnonymousAuthRequest = options.validateAnonymousAuthRequest;
    this.wss = new WebSocketServer({ noServer: true });
    // Route upgrades manually so both the authenticated hub and the anonymous
    // auth-request hub can share one WebSocketServer while keeping the ws
    // library's behaviour (destroy) for any other path.
    server.on('upgrade', (req, socket, head) => this.handleUpgrade(req, socket, head));
  }

  storeWsConnectionToken(token: string, entry: WsConnectionTokenEntry): void {
    this.wsConnectionTokens.set(token, entry);
    // Cleanup expired tokens at most once per minute (time-based, not size-based,
    // so expired tokens don't accumulate even under low traffic).
    const now = Date.now();
    if (now - this.wsTokenLastCleanupAt > 60_000) {
      this.wsTokenLastCleanupAt = now;
      for (const [key, value] of this.wsConnectionTokens) {
        if (value.expiresAt <= now) this.wsConnectionTokens.delete(key);
      }
    }
  }

  consumeWsConnectionToken(token: string): WsConnectionTokenEntry | null {
    const entry = this.wsConnectionTokens.get(token);
    if (!entry) return null;
    // Single-use: remove once consumed
    this.wsConnectionTokens.delete(token);
    if (entry.expiresAt <= Date.now()) return null;
    return entry;
  }

  private handleUpgrade(req: http.IncomingMessage, socket: Duplex, head: Buffer): void {
    let pathname: string;
    try {
      pathname = new URL(req.url || '/', 'http://localhost').pathname;
    } catch {
      socket.destroy();
      return;
    }

    if (pathname === this.hubPath) {
      this.wss.handleUpgrade(req, socket, head, (ws) => this.handleUserConnection(ws, req));
      return;
    }
    if (pathname === ANONYMOUS_HUB_PATH) {
      void this.handleAnonymousUpgrade(req, socket, head);
      return;
    }
    socket.destroy();
  }

  private rejectUpgrade(socket: Duplex, status: number, reason: string): void {
    const duplex = socket as { writable?: boolean; write?: (chunk: string) => boolean; destroy?: () => void };
    if (duplex.writable === false) return;
    try {
      duplex.write?.(`HTTP/1.1 ${status} ${reason}\r\nConnection: close\r\n\r\n`);
    } catch {
      // The client may have already gone away.
    }
    duplex.destroy?.();
  }

  private async handleAnonymousUpgrade(
    req: http.IncomingMessage,
    socket: Duplex,
    head: Buffer
  ): Promise<void> {
    const authRequestId = extractAnonymousToken(req);
    const valid = !!authRequestId && !!this.validateAnonymousAuthRequest
      ? await this.validateAnonymousAuthRequest(authRequestId)
      : false;
    if (!valid) {
      this.rejectUpgrade(socket, 401, 'Unauthorized');
      return;
    }
    this.wss.handleUpgrade(req, socket, head, (ws) => this.handleAnonymousConnection(ws, authRequestId!));
  }

  private handleUserConnection(ws: WebSocket, req: http.IncomingMessage): void {
    void (async () => {
      let userId: string;
      let deviceIdentifier: string | null = null;

      // Primary auth path: one-time ws connection token issued by /notifications/hub/negotiate
      const wsToken = extractWsConnectionToken(req);
      if (wsToken) {
        const entry = this.consumeWsConnectionToken(wsToken);
        if (!entry) {
          ws.close(1008, 'Unauthorized');
          return;
        }
        userId = entry.userId;
        deviceIdentifier = entry.deviceIdentifier;
      } else {
        // Legacy path: raw access JWT in the Authorization header (or, only when
        // explicitly enabled, the deprecated ?access_token= query parameter).
        const accessToken = extractAccessToken(req, this.allowLegacyQueryToken);
        if (!accessToken) {
          ws.close(1008, 'Unauthorized');
          return;
        }
        try {
          const payload = await verifyJWT(accessToken, this.jwtSecret);
          if (!payload?.sub) {
            ws.close(1008, 'Unauthorized');
            return;
          }
          userId = payload.sub;
          deviceIdentifier = payload.did || null;
        } catch {
          ws.close(1008, 'Unauthorized');
          return;
        }
      }

      const attachment: WsAttachment = {
        kind: 'user',
        userId,
        authRequestId: null,
        handshakeComplete: false,
        protocol: 'json',
        deviceIdentifier,
      };

      (ws as any).__attachment = attachment;

      this.addConnection(userId, ws, deviceIdentifier);

      ws.on('message', (data: Buffer, isBinary: boolean) => {
        this.handleMessage(ws, data, isBinary, attachment);
      });

      ws.on('close', () => {
        this.removeConnection(userId, ws);
        this.broadcastDeviceStatus(userId);
      });

      ws.on('error', () => {
        this.removeConnection(userId, ws);
      });
    })();
  }

  private handleAnonymousConnection(ws: WebSocket, authRequestId: string): void {
    const attachment: WsAttachment = {
      kind: 'anonymous-auth-request',
      userId: null,
      authRequestId,
      handshakeComplete: false,
      protocol: 'json',
      deviceIdentifier: null,
    };

    (ws as any).__attachment = attachment;
    this.addConnection(authRequestId, ws, null);

    ws.on('message', (data: Buffer, isBinary: boolean) => {
      this.handleMessage(ws, data, isBinary, attachment);
    });

    ws.on('close', () => {
      this.removeConnection(authRequestId, ws);
    });

    ws.on('error', () => {
      this.removeConnection(authRequestId, ws);
    });
  }

  private addConnection(key: string, ws: WebSocket, deviceIdentifier: string | null): void {
    if (!this.users.has(key)) {
      this.users.set(key, {
        sockets: new Set(),
        deviceIdentifiers: new Map(),
      });
    }
    const user = this.users.get(key)!;
    user.sockets.add(ws);
    user.deviceIdentifiers.set(ws, deviceIdentifier);
  }

  private removeConnection(key: string, ws: WebSocket): void {
    const user = this.users.get(key);
    if (user) {
      user.sockets.delete(ws);
      user.deviceIdentifiers.delete(ws);
      if (user.sockets.size === 0) {
        this.users.delete(key);
      }
    }
  }

  private handleMessage(ws: WebSocket, data: Buffer, isBinary: boolean, attachment: WsAttachment): void {
    if (!attachment.handshakeComplete) {
      // Both JSON and MessagePack clients send their handshake as JSON text.
      if (isBinary) return;
      const text = data.toString('utf-8');
      const frames = text.split(SIGNALR_RECORD_SEPARATOR).filter(Boolean);
      for (const frame of frames) {
        try {
          const handshake = JSON.parse(frame) as { protocol?: string };
          attachment.protocol = handshake?.protocol === 'messagepack' ? 'messagepack' : 'json';
          attachment.handshakeComplete = true;
          ws.send(SIGNALR_HANDSHAKE_ACK);
          if (attachment.kind === 'user') {
            this.broadcastDeviceStatus(attachment.userId!);
          }
          return;
        } catch {
          // ignore
        }
      }
      return;
    }

    if (isBinary) {
      // MessagePack clients ping with binary frames; echo them back the same
      // way the upstream Durable Object does.
      try {
        ws.send(data);
      } catch {
        // ignore
      }
      return;
    }

    try {
      const ping = JSON.parse(data.toString('utf-8'));
      if (ping.type === 6) {
        ws.send(JSON.stringify({ type: 6 }) + SIGNALR_RECORD_SEPARATOR);
      }
    } catch {
      // ignore
    }
  }

  private sendSignalR(
    ws: WebSocket,
    updateType: number,
    payload: Record<string, unknown>,
    contextId: string | null,
    target: string = 'ReceiveMessage'
  ): void {
    const attachment = (ws as any).__attachment as WsAttachment | undefined;
    if (attachment?.protocol === 'messagepack') {
      ws.send(buildSignalRMessagePackInvocation(updateType, payload, contextId, target));
    } else {
      ws.send(buildSignalRJsonInvocation(updateType, payload, contextId, target));
    }
  }

  private broadcastDeviceStatus(userId: string): void {
    this.broadcastMessage(userId, SIGNALR_UPDATE_TYPE_DEVICE_STATUS, {
      UserId: userId,
      Date: new Date().toISOString(),
    });
  }

  broadcastMessage(
    key: string,
    updateType: number,
    payload: Record<string, unknown>,
    contextId: string | null = null,
    targetDeviceIdentifier: string | null = null
  ): void {
    const user = this.users.get(key);
    if (!user) return;

    for (const ws of user.sockets) {
      if (ws.readyState !== WebSocket.OPEN) continue;

      const attachment = (ws as any).__attachment as WsAttachment | undefined;
      if (!attachment?.handshakeComplete) continue;

      if (targetDeviceIdentifier && attachment.deviceIdentifier !== targetDeviceIdentifier) {
        continue;
      }

      try {
        this.sendSignalR(ws, updateType, payload, contextId);
      } catch {
        // ignore
      }
    }
  }

  broadcastAuthRequestResponse(authRequestId: string, userId: string, contextId: string | null): void {
    const connections = this.users.get(authRequestId);
    if (!connections) return;

    const payload = {
      UserId: userId,
      Id: authRequestId,
    };
    for (const ws of connections.sockets) {
      if (ws.readyState !== WebSocket.OPEN) continue;
      const attachment = (ws as any).__attachment as WsAttachment | undefined;
      if (!attachment?.handshakeComplete) continue;
      if (attachment.kind !== 'anonymous-auth-request' || attachment.authRequestId !== authRequestId) {
        continue;
      }
      try {
        this.sendSignalR(
          ws,
          SIGNALR_UPDATE_TYPE_AUTH_REQUEST_RESPONSE,
          payload,
          contextId,
          'AuthRequestResponseRecieved'
        );
      } catch {
        // ignore
      }
    }
  }

  notifyVaultSync(userId: string, revisionDate: string, contextId?: string | null): void {
    this.broadcastMessage(
      userId,
      SIGNALR_UPDATE_TYPE_SYNC_VAULT,
      {
        UserId: userId,
        Date: revisionDate,
      },
      contextId ?? null
    );
  }

  notifyLogout(userId: string, targetDeviceIdentifier?: string | null): void {
    this.broadcastMessage(
      userId,
      SIGNALR_UPDATE_TYPE_LOG_OUT,
      {
        UserId: userId,
        Date: new Date().toISOString(),
      },
      null,
      targetDeviceIdentifier ?? null
    );
  }

  notifyBackupProgress(
    userId: string,
    progress: {
      operation: 'backup-restore' | 'backup-export' | 'backup-remote-run';
      source?: 'local' | 'remote';
      step: string;
      fileName: string;
      stageTitle?: string;
      stageDetail?: string;
      replaceExisting?: boolean;
      done?: boolean;
      ok?: boolean;
      error?: string | null;
      timestamp?: string;
    },
    targetDeviceIdentifier?: string | null
  ): void {
    this.broadcastMessage(
      userId,
      SIGNALR_UPDATE_TYPE_BACKUP_RESTORE_PROGRESS,
      {
        UserId: userId,
        Date: progress.timestamp || new Date().toISOString(),
        ...progress,
      },
      null,
      targetDeviceIdentifier ?? null
    );
  }

  getOnlineDeviceIdentifiers(userId: string): string[] {
    const user = this.users.get(userId);
    if (!user) return [];

    const identifiers = new Set<string>();
    for (const [ws, deviceId] of user.deviceIdentifiers) {
      if (deviceId && ws.readyState === WebSocket.OPEN) {
        const attachment = (ws as any).__attachment as WsAttachment | undefined;
        if (attachment?.handshakeComplete) {
          identifiers.add(deviceId);
        }
      }
    }
    return Array.from(identifiers);
  }

  close(): void {
    for (const user of this.users.values()) {
      for (const ws of user.sockets) {
        try {
          ws.terminate();
        } catch {
          // Ignore sockets that already closed.
        }
      }
    }
    this.users.clear();
    this.wsConnectionTokens.clear();
    this.wss.close();
  }
}

export class NotificationsHubNamespace {
  private server: NotificationsHubServer;

  constructor(server: NotificationsHubServer) {
    this.server = server;
  }

  idFromName(_name: string): string {
    return _name;
  }

  get(id: string): NotificationsHubStub {
    return new NotificationsHubStub(id, this.server);
  }
}

export class NotificationsHubStub {
  private userId: string;
  private server: NotificationsHubServer;

  constructor(userId: string, server: NotificationsHubServer) {
    this.userId = userId;
    this.server = server;
  }

  async fetch(input: RequestInfo | URL, init?: RequestInit): Promise<Response> {
    // Mirror BackupTransferRunnerStub: accept plain strings, URL objects and
    // Request objects. Request.toString() is '[object Request]', which would
    // throw 'Invalid URL' when passed to the URL constructor.
    const url = typeof input === 'string'
      ? new URL(input, 'http://localhost')
      : new URL(input instanceof URL ? input.href : (input as Request).url);
    const pathname = url.pathname;

    // Negotiate flow: store a short-lived ws connection token (single-use)
    if (pathname === '/internal/ws-token') {
      const body = init?.body ? JSON.parse(init.body as string) : {};
      const token = String(body.token || '').trim();
      if (!token) return new Response('token is required', { status: 400 });
      this.server.storeWsConnectionToken(token, {
        userId: String(body.userId || this.userId),
        deviceIdentifier: body.deviceIdentifier ?? null,
        expiresAt: Number(body.expiresAt || (Date.now() + 60_000)),
      });
      return new Response(null, { status: 204 });
    }

    // Ws upgrade flow: consume the one-time token and return the bound connection
    if (pathname === '/internal/ws-token/consume') {
      const body = init?.body ? JSON.parse(init.body as string) : {};
      const token = String(body.token || '').trim();
      if (!token) return new Response('token is required', { status: 400 });
      const entry = this.server.consumeWsConnectionToken(token);
      if (!entry) return new Response('token not found or expired', { status: 404 });
      return new Response(JSON.stringify({ userId: entry.userId, deviceIdentifier: entry.deviceIdentifier ?? null }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    if (pathname === '/internal/notify') {
      const body = init?.body ? JSON.parse(init.body as string) : {};
      const updateType = body.updateType || SIGNALR_UPDATE_TYPE_SYNC_VAULT;
      const contextId = body.contextId || null;
      const targetDeviceIdentifier = body.targetDeviceIdentifier || null;
      const payload = body.payload || {};

      this.server.broadcastMessage(this.userId, updateType, payload, contextId, targetDeviceIdentifier);

      return new Response(null, { status: 204 });
    }

    if (pathname === '/internal/online') {
      const deviceIdentifiers = this.server.getOnlineDeviceIdentifiers(this.userId);
      return new Response(JSON.stringify({ deviceIdentifiers }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // Auth request response broadcast: mirrors the upstream Durable Object by
    // pushing "AuthRequestResponseRecieved" to the anonymous sockets waiting
    // on this auth request id.
    if (pathname === '/internal/auth-request-response') {
      const body = init?.body ? JSON.parse(init.body as string) : {};
      const userId = String(body.userId || '').trim();
      const authRequestId = String(body.authRequestId || this.userId).trim();
      if (!userId || !authRequestId) return new Response('Invalid auth request notification', { status: 400 });

      this.server.broadcastAuthRequestResponse(
        authRequestId,
        userId,
        String(body.contextId || '').trim() || null
      );
      return new Response(null, { status: 204 });
    }

    return new Response('Not found', { status: 404 });
  }
}

export function createNotificationsHub(
  server: http.Server,
  jwtSecret: string,
  path?: string,
  options?: NotificationsHubOptions
): NotificationsHubServer {
  return new NotificationsHubServer(server, jwtSecret, path, options);
}

export function createNotificationsHubNamespace(server: NotificationsHubServer): NotificationsHubNamespace {
  return new NotificationsHubNamespace(server);
}

export type DurableObjectNamespace = NotificationsHubNamespace;
