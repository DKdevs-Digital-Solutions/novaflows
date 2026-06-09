// Em desenvolvimento use: node --env-file=server/.env server/index.js
// No Docker as vars vêm direto do compose/Portainer — sem dotenv necessário.

import express from 'express';
import cors from 'cors';
import fetch from 'node-fetch';
import { handleWhatsAppFlows } from './whatsapp-flows.js';

const app = express();
const PORT = process.env.PORT || 3001;

app.use(cors());
app.use(express.json());

// ─── MapSis proxy (espelha o Cloudflare Worker em desenvolvimento) ────────────

const ALLOWLIST = new Set([
  'get_lojas', 'get_servicos', 'get_cliente', 'set_cliente',
  'get_consultores', 'get_boxes', 'get_lista_agendamentos',
  'get_agenda_horario_disponivel', 'set_agendamento',
]);

app.get('/api/mapsis/:method', async (req, res) => {
  const { method } = req.params;

  if (!ALLOWLIST.has(method)) {
    return res.status(400).json({ error: 'Método não permitido' });
  }

  const { MAPSIS_URL, MAPSIS_USER, MAPSIS_PASS, MAPSIS_KEY } = process.env;
  if (!MAPSIS_URL || !MAPSIS_USER || !MAPSIS_PASS || !MAPSIS_KEY) {
    return res.status(500).json({ error: 'Servidor sem credenciais do MapSis' });
  }

  try {
    const outUrl = new URL(`${MAPSIS_URL.replace(/\/$/, '')}/${method}.asp`);
    outUrl.searchParams.set('usuario', MAPSIS_USER);
    outUrl.searchParams.set('senha', MAPSIS_PASS);
    outUrl.searchParams.set('chave', MAPSIS_KEY);
    outUrl.searchParams.set('encode', 'true');

    for (const [k, v] of Object.entries(req.query)) {
      outUrl.searchParams.set(k, String(v));
    }

    const response = await fetch(outUrl.toString(), {
      headers: { Accept: 'application/json, text/plain, */*' },
    });

    const text = await response.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { raw: text }; }

    if (!response.ok) {
      return res.status(502).json({ error: 'Falha ao chamar MapSis', details: data });
    }
    res.json(data);
  } catch (err) {
    res.status(500).json({ error: 'Erro interno no proxy', details: err.message });
  }
});

// ─── WhatsApp Flows ───────────────────────────────────────────────────────────

app.get('/whatsapp/flows', (_req, res) => {
  res.json({ status: 'active', timestamp: new Date().toISOString() });
});

app.post('/whatsapp/flows', handleWhatsAppFlows);

// ─────────────────────────────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
  console.log(`  MapSis proxy : http://localhost:${PORT}/api/mapsis/<método>`);
  console.log(`  WA Flows     : http://localhost:${PORT}/whatsapp/flows`);
});
