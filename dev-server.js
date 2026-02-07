const express = require('express');
const path = require('path');
require('dotenv').config();

const app = express();
app.use(express.json());

// Load compiled handler, fallback to TS source during dev if not compiled
const handlerPath = path.join(__dirname, 'dist', 'api', 'mpc-party1.js');
let handlerModule;
try {
  handlerModule = require(handlerPath);
} catch (err) {
  try {
    handlerModule = require('./api/mpc-party1');
  } catch (err2) {
    console.error('Could not load handler from', handlerPath, 'or', './api/mpc-party1', err, err2);
    process.exit(1);
  }
}

const handler = handlerModule && (handlerModule.default || handlerModule.handler || handlerModule);
if (typeof handler !== 'function') {
  console.error('Handler is not a function. Export default function expected.');
  process.exit(1);
}

// Root endpoint
app.get('/', (req, res) => {
  res.json({
    status: 'online',
    service: 'Party 1 MPC Node',
    endpoints: {
      'POST /api/mpc-party1': 'Store share or partial key',
      'GET /api/mpc-party1': 'Retrieve partial key',
    },
  });
});

app.post('/api/mpc-party1', (req, res) => {
  try {
    handler(req, res);
  } catch (err) {
    console.error('Handler error', err);
    res.status(500).json({ error: 'handler error', details: err.message });
  }
});

app.get('/api/mpc-party1', (req, res) => {
  try {
    handler(req, res);
  } catch (err) {
    console.error('Handler error', err);
    res.status(500).json({ error: 'handler error', details: err.message });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Dev server listening on http://localhost:${port}`);
  console.log(`  Root: http://localhost:${port}/`);
  console.log(`  Party 1 API: http://localhost:${port}/api/mpc-party1`);
});
