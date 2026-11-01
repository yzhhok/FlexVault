import assert from 'node:assert/strict';
import test from 'node:test';
import http from 'node:http';
import type { AddressInfo } from 'node:net';
import { WebSocket } from 'ws';

import {
  createNotificationsHub,
  NotificationsHubServer,
  NotificationsHubStub,
  type NotificationsHubOptions,
} from '../src/selfhosted/websocket';
import { createJWT } from '../src/utils/jwt';

const secret = 'selfhosted-websocket-test-secret-32-bytes';
const hubPath = '/notifications/hub';
const anonymousHubPath = '/notifications/anonymous-hub';

async function accessToken(userId: string): Promise<string> {
  return createJWT(
    {
      sub: userId,
      email: 'user@example.test',
      name: 'Test User',
      sstamp: 'security-stamp',
    },
    secret
  );
}

async function startHub(options?: NotificationsHubOptions): Promise<{
  server: http.Server;
  hub: NotificationsHubServer;
  url: string;
  anonymousUrl: string;
}> {
  const server = http.createServer();
  const hub = createNotificationsHub(server, secret, hubPath, options);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  return {
    server,
    hub,
    url: `ws://127.0.0.1:${port}${hubPath}`,
    anonymousUrl: `ws://127.0.0.1:${port}${anonymousHubPath}`,
  };
}

async function stop(server: http.Server, hub: NotificationsHubServer): Promise<void> {
  hub.close();
  await new Promise<void>((resolve) => server.close(() => resolve()));
}

/**
 * The server always completes the websocket handshake before validating the
 * token, so a rejected client still sees `open` before the 1008 close frame.
 */
function waitOpen(ws: WebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    ws.once('open', () => resolve());
    ws.once('error', reject);
    ws.once('close', () => reject(new Error('closed before opening')));
  });
}

function waitClose(ws: WebSocket): Promise<number> {
  return new Promise((resolve, reject) => {
    ws.once('close', (code) => resolve(code));
    ws.once('error', () => resolve(-1));
  });
}

function closeClient(ws: WebSocket): Promise<void> {
  return new Promise((resolve) => {
    if (ws.readyState === WebSocket.CLOSED) return resolve();
    ws.once('close', () => resolve());
    ws.close();
  });
}

test('raw access tokens in the query string are rejected by default', async (t) => {
  const { server, hub, url } = await startHub();
  t.after(() => stop(server, hub));

  const token = await accessToken('user-1');
  const ws = new WebSocket(`${url}?access_token=${encodeURIComponent(token)}`);
  t.after(() => ws.terminate());

  assert.equal(await waitClose(ws), 1008);
});

test('deprecated query tokens still work when explicitly enabled', async (t) => {
  const { server, hub, url } = await startHub({ allowLegacyQueryToken: true });
  t.after(() => stop(server, hub));

  const token = await accessToken('user-1');
  const ws = new WebSocket(`${url}?access_token=${encodeURIComponent(token)}`);
  t.after(() => ws.terminate());

  await waitOpen(ws);
  await closeClient(ws);
});

test('Authorization bearer tokens authenticate the websocket', async (t) => {
  const { server, hub, url } = await startHub();
  t.after(() => stop(server, hub));

  const token = await accessToken('user-1');
  const ws = new WebSocket(url, { headers: { Authorization: `Bearer ${token}` } });
  t.after(() => ws.terminate());

  await waitOpen(ws);
  await closeClient(ws);
});

test('one-time connection tokens are accepted only once', async (t) => {
  const { server, hub, url } = await startHub();
  t.after(() => stop(server, hub));

  hub.storeWsConnectionToken('ticket-1', {
    userId: 'user-2',
    deviceIdentifier: 'device-1',
    expiresAt: Date.now() + 60_000,
  });

  const first = new WebSocket(`${url}?id=ticket-1`);
  t.after(() => first.terminate());
  await waitOpen(first);
  await closeClient(first);

  const second = new WebSocket(`${url}?id=ticket-1`);
  t.after(() => second.terminate());
  assert.equal(await waitClose(second), 1008);
});

test('expired connection tokens are rejected', async (t) => {
  const { server, hub, url } = await startHub();
  t.after(() => stop(server, hub));

  hub.storeWsConnectionToken('ticket-expired', {
    userId: 'user-2',
    deviceIdentifier: null,
    expiresAt: Date.now() - 1000,
  });

  const ws = new WebSocket(`${url}?id=ticket-expired`);
  t.after(() => ws.terminate());
  assert.equal(await waitClose(ws), 1008);
});

function waitMessage(ws: WebSocket): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    ws.once('message', (data) => resolve(Buffer.from(data)));
    ws.once('error', reject);
  });
}

function waitForMessageMatching(
  ws: WebSocket,
  predicate: (data: Buffer) => boolean,
  timeoutMs = 3000
): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('timed out waiting for message')), timeoutMs);
    ws.on('message', (data) => {
      const buf = Buffer.from(data);
      if (predicate(buf)) {
        clearTimeout(timer);
        resolve(buf);
      }
    });
    ws.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

function waitUpgradeFailure(ws: WebSocket): Promise<void> {
  return new Promise((resolve, reject) => {
    ws.once('error', () => resolve());
    ws.once('open', () => reject(new Error('connection unexpectedly opened')));
  });
}

test('stub fetch accepts Request objects forwarded by upstream handlers', async (t) => {
  const { server, hub } = await startHub();
  t.after(() => stop(server, hub));

  const stub = new NotificationsHubStub('user-request-obj', hub);

  // Request.toString() is '[object Request]'; this used to throw Invalid URL.
  const online = await stub.fetch(new Request('https://notifications/internal/online'));
  assert.equal(online.status, 200);

  const stored = await stub.fetch(new Request('https://notifications/internal/ws-token'), {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      token: 'ticket-via-request',
      userId: 'user-request-obj',
      deviceIdentifier: null,
      expiresAt: Date.now() + 60_000,
    }),
  });
  assert.equal(stored.status, 204);
  assert.ok(hub.consumeWsConnectionToken('ticket-via-request'));
});

test('anonymous hub requires a valid auth request token', async (t) => {
  const { server, hub, anonymousUrl } = await startHub({
    validateAnonymousAuthRequest: async (id) => id === 'auth-request-1',
  });
  t.after(() => stop(server, hub));

  const invalid = new WebSocket(`${anonymousUrl}?Token=missing-request`);
  t.after(() => invalid.terminate());
  await waitUpgradeFailure(invalid);
});

test('anonymous hub rejects upgrades when no validator is configured', async (t) => {
  const { server, hub, anonymousUrl } = await startHub();
  t.after(() => stop(server, hub));

  const ws = new WebSocket(`${anonymousUrl}?Token=auth-request-1`);
  t.after(() => ws.terminate());
  await waitUpgradeFailure(ws);
});

test('auth request responses reach anonymous subscribers', async (t) => {
  const { server, hub, anonymousUrl } = await startHub({
    validateAnonymousAuthRequest: async (id) => id === 'auth-request-2',
  });
  t.after(() => stop(server, hub));

  const ws = new WebSocket(`${anonymousUrl}?Token=auth-request-2`);
  t.after(() => ws.terminate());
  await waitOpen(ws);

  // SignalR JSON handshake; the hub replies with the empty handshake ack.
  ws.send(`{"protocol":"json","version":1}${String.fromCharCode(0x1e)}`);
  const ack = await waitMessage(ws);
  assert.equal(ack.toString('utf-8').replace(/\x1e/g, ''), '{}');

  // Mirror the upstream notifyAuthRequestResponse call through the stub.
  const stub = new NotificationsHubStub('auth-request-2', hub);
  const response = await stub.fetch('https://notifications/internal/auth-request-response', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      userId: 'approver-user',
      authRequestId: 'auth-request-2',
      contextId: null,
    }),
  });
  assert.equal(response.status, 204);

  const message = await waitForMessageMatching(ws, (buf) =>
    buf.includes(Buffer.from('AuthRequestResponseRecieved'))
  );
  const text = message.toString('utf-8');
  assert.match(text, /"approver-user"/);
  assert.match(text, /"auth-request-2"/);

  await closeClient(ws);
});

test('messagepack subscribers receive binary notifications', async (t) => {
  const { server, hub, url } = await startHub();
  t.after(() => stop(server, hub));

  const token = await accessToken('user-messagepack');
  const ws = new WebSocket(url, { headers: { Authorization: `Bearer ${token}` } });
  t.after(() => ws.terminate());
  await waitOpen(ws);

  ws.send(`{"protocol":"messagepack","version":1}${String.fromCharCode(0x1e)}`);
  const ack = await waitMessage(ws);
  assert.equal(ack.toString('utf-8').replace(/\x1e/g, ''), '{}');

  hub.notifyVaultSync('user-messagepack', 'messagepack-probe-revision');

  const frame = await waitForMessageMatching(ws, (buf) =>
    buf.includes(Buffer.from('messagepack-probe-revision'))
  );
  // MessagePack hub protocol frames are binary [1, {}, null, target, args, []]
  // with a varint length prefix, so the frame must not start with JSON '{'.
  assert.notEqual(frame[0], 0x7b);
  assert.ok(frame.includes(Buffer.from('ReceiveMessage')));

  await closeClient(ws);
});
