import type { FastifyInstance } from 'fastify';
import { buildAuthenticate, requireUser } from '../middleware/auth.js';
import { PLAN_QUOTAS } from '../auth/usage.js';
import { generatePdfReport } from '../reports/pdf.js';
import { generateDocxReport } from '../reports/docx.js';
import { generateMarkdownReport } from '../reports/markdown.js';
import type { ScanRouteDeps } from './scans.js';

const FORMATS = ['pdf', 'docx', 'md', 'json'] as const;
type ReportFormat = (typeof FORMATS)[number];

const CONTENT_TYPES: Record<ReportFormat, string> = {
  pdf: 'application/pdf',
  docx: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  md: 'text/markdown',
  json: 'application/json',
};

export async function reportRoutes(app: FastifyInstance, deps: ScanRouteDeps): Promise<void> {
  const { db } = deps;
  const authenticate = buildAuthenticate(db);

  app.get('/api/scans/:id/report', { preHandler: authenticate }, async (request, reply) => {
    const user = requireUser(request);
    const { id } = request.params as { id: string };
    const query = request.query as { format?: string };
    const format = (query.format ?? 'pdf') as ReportFormat;

    if (!FORMATS.includes(format)) {
      return reply.status(400).send({ error: `format must be one of: ${FORMATS.join(', ')}` });
    }
    if (!PLAN_QUOTAS[user.plan].reportFormats.includes(format)) {
      return reply
        .status(403)
        .send({ error: `The ${format.toUpperCase()} report format requires the Hunter plan or higher` });
    }

    const scan = await db.getScan(id);
    if (!scan || scan.userId !== user.id) {
      return reply.status(404).send({ error: 'Scan not found' });
    }
    if (scan.status !== 'completed') {
      return reply.status(409).send({ error: `Report is only available for completed scans (current: ${scan.status})` });
    }

    const findings = await db.listFindings(id);
    const input = { scan, findings, generatedBy: `BugSeek AI backend (${user.email})` };

    await db.recordUsage(user.id, 'report', 1, id);

    const filename = `bugseek-report-${id.slice(0, 8)}.${format}`;
    reply.header('content-type', CONTENT_TYPES[format]);
    reply.header('content-disposition', `attachment; filename="${filename}"`);

    switch (format) {
      case 'pdf':
        return reply.send(await generatePdfReport(input));
      case 'docx':
        return reply.send(await generateDocxReport(input));
      case 'md':
        return reply.send(generateMarkdownReport(input));
      case 'json':
        return reply.send({ scan, findings });
    }
  });
}
