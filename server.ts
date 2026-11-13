import dotenv from 'dotenv';
import express from 'express';
import type { Request, Response } from 'express';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  handleAnalyzeMessageRequest,
  handleAnalyzeQrRequest,
  handleAnalyzeUrlRequest,
  handleAssistantChatRequest,
  handleExplainRetryRequest,
  handleHealthRequest,
  handleRescoreScansRequest,
} from './server/scannerHandlers.ts';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const PORT = 3000;

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', async (req: Request, res: Response) => {
    const probeParam = typeof req.query.probe === 'string' ? req.query.probe : undefined;
    const modelParam = typeof req.query.model === 'string' ? req.query.model : undefined;
    const result = await handleHealthRequest(probeParam, modelParam);
    res.status(result.status).json(result.body);
  });

  app.post('/api/analyze/url', async (req: Request, res: Response) => {
    const result = await handleAnalyzeUrlRequest(req.body);
    res.status(result.status).json(result.body);
  });

  app.post('/api/analyze/message', async (req: Request, res: Response) => {
    const result = await handleAnalyzeMessageRequest(req.body);
    res.status(result.status).json(result.body);
  });

  app.post('/api/analyze/qr', async (req: Request, res: Response) => {
    const result = await handleAnalyzeQrRequest(req.body);
    res.status(result.status).json(result.body);
  });

  app.post('/api/analyze/explain', async (req: Request, res: Response) => {
    const result = await handleExplainRetryRequest(req.body);
    res.status(result.status).json(result.body);
  });

  app.post('/api/scans/rescore', async (req: Request, res: Response) => {
    const result = await handleRescoreScansRequest(req.body);
    res.status(result.status).json(result.body);
  });

  app.post('/api/assistant/chat', async (req: Request, res: Response) => {
    const result = await handleAssistantChatRequest(req.body);
    res.status(result.status).json(result.body);
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distPath = path.join(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`PhishShield AI server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start PhishShield AI server:', err);
  process.exit(1);
});
