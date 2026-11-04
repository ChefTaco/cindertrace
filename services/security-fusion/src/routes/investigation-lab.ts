import type { Hono, Context } from 'hono';
import { labDecisionSchema, labTransitionSchema, labStatusSchema } from '@cindertrace/contracts';
import { z, type ZodType } from 'zod';
import type { AppVariables } from '../types/index.js';
import { getUser, requireRole } from '../middleware/auth.js';
import { HttpError } from '../middleware/error-handler.js';
import { compareLab, decideLabSimulation, listLabRuns, readLab, requireLab, startLab, transitionLab } from '../services/investigation-lab.js';

async function input<T>(c: Context<AppVariables>, schema: ZodType<T>): Promise<T> {
  const parsed = schema.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) throw new HttpError(400, 'VALIDATION_ERROR', parsed.error.issues.map(x => x.message).join('; '));
  return parsed.data;
}
export function registerLabRoutes(router: Hono<AppVariables>) {
  router.get('/lab', async c => c.json({ success: true, data: labStatusSchema.parse({ enabled: process.env['CINDERTRACE_LAB_ENABLED'] === 'true', canAdmin: getUser(c).role === 'ADMIN', runs: process.env['CINDERTRACE_LAB_ENABLED'] === 'true' ? (await listLabRuns()).map(row => ({...row, createdAt: row.createdAt.toISOString()})) : [] }) }));
  router.use('/lab/*', async (_c, next) => { requireLab(); await next(); });
  router.post('/lab/runs', requireRole('ADMIN'), async c => {
    await input(c, z.object({}).strict());
    return c.json({ success: true, data: await startLab(getUser(c).userId) }, 201);
  });
  router.get('/lab/runs/:id', async c => c.json({ success: true, data: await readLab(c.req.param('id')!, getUser(c).role === 'ADMIN') }));
  router.post('/lab/runs/:id/advance', async c => c.json({ success: true, data: await transitionLab(c.req.param('id')!, await input(c, labTransitionSchema), getUser(c).userId, false) }));
  router.post('/lab/runs/:id/complete', async c => c.json({ success: true, data: await transitionLab(c.req.param('id')!, await input(c, labTransitionSchema), getUser(c).userId, true) }));
  router.post('/lab/runs/:id/restart', requireRole('ADMIN'), async c => {
    await input(c, z.object({}).strict());
    return c.json({ success: true, data: await startLab(getUser(c).userId, c.req.param('id')!) }, 201);
  });
  router.get('/lab/runs/:id/comparison', async c => c.json({ success: true, data: await compareLab(c.req.param('id')!, getUser(c).role === 'ADMIN') }));
  router.post('/lab/runs/:id/simulations/:simulationId/decision', requireRole('ADMIN'), async c => c.json({ success: true, data: await decideLabSimulation(c.req.param('id')!, c.req.param('simulationId')!, await input(c, labDecisionSchema), getUser(c).userId) }));
}
