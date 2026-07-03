/**
 * Realtime hub: one WebSocket endpoint (/ws?token=JWT). Each authenticated
 * user gets a connection set; events are pushed only to the endpoints of a
 * message. Payloads are the same encrypted blobs stored in the database —
 * nothing readable transits this channel either.
 */
import { WebSocketServer } from 'ws';
import { verifyToken } from './auth.js';

const connections = new Map(); // userId -> Set<ws>

export function attachRealtime(httpServer) {
  const wss = new WebSocketServer({ noServer: true });

  httpServer.on('upgrade', (req, socket, head) => {
    const url = new URL(req.url, 'http://localhost');
    if (url.pathname !== '/ws') {
      socket.destroy();
      return;
    }
    const userId = verifyToken(url.searchParams.get('token') ?? '');
    if (!userId) {
      socket.write('HTTP/1.1 401 Unauthorized\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => {
      let set = connections.get(userId);
      if (!set) {
        set = new Set();
        connections.set(userId, set);
      }
      set.add(ws);
      ws.on('close', () => {
        set.delete(ws);
        if (set.size === 0) connections.delete(userId);
      });
      // Keepalive so proxies/phones don't silently drop the socket.
      ws.isAlive = true;
      ws.on('pong', () => {
        ws.isAlive = true;
      });
    });
  });

  const interval = setInterval(() => {
    for (const set of connections.values()) {
      for (const ws of set) {
        if (!ws.isAlive) {
          ws.terminate();
          continue;
        }
        ws.isAlive = false;
        ws.ping();
      }
    }
  }, 30000);
  httpServer.on('close', () => clearInterval(interval));
}

export function sendTo(userId, event) {
  const set = connections.get(userId);
  if (!set) return false;
  const data = JSON.stringify(event);
  for (const ws of set) {
    if (ws.readyState === ws.OPEN) ws.send(data);
  }
  return set.size > 0;
}

export function isOnline(userId) {
  return connections.has(userId);
}
