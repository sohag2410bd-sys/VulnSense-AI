import 'dotenv/config';
import express from 'express';
import fs from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import JSZip from 'jszip';
import { createServer as createViteServer } from 'vite';
import type { DeliverableFile, ScanReport } from './src/types/recon';
import { runPassiveRecon } from './src/server/recon';
import { analyzeReconWithGemini } from './src/server/gemini';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = 3000;

const DELIVERABLE_SPECS: Array<{
  relPath: string;
  name: string;
  language: string;
  description: string;
}> = [
  {
    relPath: 'requirements.txt',
    name: 'requirements.txt',
    language: 'text',
    description: 'Python package dependencies (google-genai, requests, rich, flask, pydantic).',
  },
  {
    relPath: 'scanner.py',
    name: 'scanner.py',
    language: 'python',
    description: 'Core passive recon module (headers, TLS, cookies, robots.txt) and Gemini structured JSON analyzer.',
  },
  {
    relPath: 'cli.py',
    name: 'cli.py',
    language: 'python',
    description: 'Adaptive Termux vertical cards and Linux multi-column Rich CLI interface with Markdown auto-export.',
  },
  {
    relPath: 'app.py',
    name: 'app.py',
    language: 'python',
    description: 'Flask web backend exposing /api/scan and /api/report/markdown routes.',
  },
  {
    relPath: 'templates/index.html',
    name: 'templates/index.html',
    language: 'html',
    description: 'Dark SOC Flask web frontend template with Tailwind CSS, risk cards, and interactive accordions.',
  },
  {
    relPath: 'README.md',
    name: 'README.md',
    language: 'markdown',
    description: 'Installation & usage guide for Termux (Android), Linux, and GitHub deployment.',
  },
];

async function loadDeliverables(): Promise<DeliverableFile[]> {
  const pkgRoot = path.resolve(__dirname, 'python_package');
  const results: DeliverableFile[] = [];

  for (const spec of DELIVERABLE_SPECS) {
    const absPath = path.join(pkgRoot, spec.relPath);
    const content = await fs.readFile(absPath, 'utf-8');
    results.push({
      path: spec.relPath,
      name: spec.name,
      language: spec.language,
      description: spec.description,
      content,
    });
  }
  return results;
}

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'VulnSense AI' });
  });

  app.post('/api/scan', async (req, res) => {
    const rawUrl = typeof req.body?.url === 'string' ? req.body.url : '';
    if (!rawUrl.trim()) {
      res.status(400).json({ error: 'Please enter a target website URL or domain.' });
      return;
    }

    try {
      const recon = await runPassiveRecon(rawUrl);
      const analysis = await analyzeReconWithGemini(recon);
      const report: ScanReport = {
        id: `scan-${Date.now()}`,
        isSample: false,
        recon,
        analysis,
      };
      res.json(report);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Unexpected scan error';
      const isValidation =
        message.includes('Invalid URL') ||
        message.includes('Please enter') ||
        message.includes('cannot be scanned') ||
        message.includes('Blocked scan') ||
        message.includes('Only HTTP');
      const isOverload =
        message.includes('503') ||
        message.toLowerCase().includes('high demand') ||
        message.toLowerCase().includes('overloaded') ||
        message.toLowerCase().includes('unavailable');

      if (isOverload) {
        res.status(503).json({
          error:
            'AI analysis models are temporarily experiencing high demand after retries and fallback. Please retry in a few moments.',
        });
        return;
      }

      res.status(isValidation ? 400 : 500).json({ error: message });
    }
  });

  app.get('/api/deliverables', async (_req, res) => {
    try {
      const files = await loadDeliverables();
      res.json({ files });
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Unable to read deliverables',
      });
    }
  });

  app.get('/api/deliverables/zip', async (_req, res) => {
    try {
      const files = await loadDeliverables();
      const zip = new JSZip();
      const root = zip.folder('vulnsense-ai');
      for (const file of files) {
        root?.file(file.path, file.content);
      }
      const buffer = await zip.generateAsync({ type: 'nodebuffer' });
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="vulnsense-ai-python.zip"');
      res.send(buffer);
    } catch (err) {
      res.status(500).json({
        error: err instanceof Error ? err.message : 'Unable to build zip archive',
      });
    }
  });

  if (process.env.NODE_ENV === 'production') {
    const distPath = path.resolve(__dirname, 'dist');
    app.use(express.static(distPath));
    app.get('*', (_req, res) => {
      res.sendFile(path.join(distPath, 'index.html'));
    });
  } else {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`VulnSense AI server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start VulnSense AI server:', err);
  process.exit(1);
});
