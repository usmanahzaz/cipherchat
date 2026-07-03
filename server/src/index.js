/**
 * CipherChat server — zero configuration.
 *
 *   npm install && npm start
 *
 * Creates its own SQLite database (data/cipherchat.db) and JWT secret on
 * first run, serves the REST API + realtime WebSocket, and prints the LAN
 * URLs phones can reach. The server only ever handles encrypted blobs.
 */
import { createServer } from 'node:http';
import { networkInterfaces } from 'node:os';
import express from 'express';
import { attachRealtime } from './realtime.js';
import { router } from './routes.js';

const PORT = Number(process.env.PORT ?? 4000);

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '256kb' }));

app.get('/', (_req, res) => res.json({ name: 'cipherchat-server', ok: true }));
app.use(router);

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal server error.' });
});

const server = createServer(app);
attachRealtime(server);

server.listen(PORT, '0.0.0.0', () => {
  const addresses = Object.values(networkInterfaces())
    .flat()
    .filter((i) => i && i.family === 'IPv4' && !i.internal)
    .map((i) => i.address);
  console.log('CipherChat server running (encrypted blobs only — nothing readable here).');
  console.log(`  local:   http://localhost:${PORT}`);
  for (const a of addresses) console.log(`  network: http://${a}:${PORT}   ← phones on your Wi-Fi use this`);
  console.log('The mobile app auto-detects this server when run via `npx expo start` on the same machine.');
});
