import { describe, expect, it } from 'vitest';
import {
  agentEntityValue,
  parseAgentEntityValue,
  securityFusionCaseEntityFilterSchema,
  securityFusionEntityRefSchema,
  securityFusionEntityTypeSchema,
} from './index.js';

describe('agent entity values', () => {
  it('adds agent without changing the existing entity types', () => {
    expect(securityFusionEntityTypeSchema.options).toEqual([
      'user', 'host', 'device', 'ip', 'service', 'account', 'domain', 'agent',
    ]);
  });

  it('parses the canonical actor form and both aliases exactly', () => {
    expect(parseAgentEntityValue(' actor:ardent-writer-1a2b3c4d ')).toEqual({
      kind: 'actor', actorId: 'ardent-writer-1a2b3c4d', value: 'actor:ardent-writer-1a2b3c4d',
    });
    expect(parseAgentEntityValue('agent-ref:node-1~Writer')).toEqual({
      kind: 'agent-ref', agentRef: 'node-1~Writer', nodeId: 'node-1', profile: 'Writer', value: 'agent-ref:node-1~Writer',
    });
    expect(parseAgentEntityValue('magnus-node:node-1')).toEqual({
      kind: 'magnus-node', nodeId: 'node-1', value: 'magnus-node:node-1',
    });
    expect(agentEntityValue.actor('lead')).toBe('actor:lead');
  });

  it('rejects malformed agent values', () => {
    for (const value of [
      'lead', 'actor:', 'actor:a', 'actor:UPPER', 'actor:' + 'a'.repeat(33), 'actor:bad id',
      'agent-ref:node-1', 'agent-ref:~writer', 'agent-ref:node-1~', 'agent-ref:a~b~c',
      'agent-ref:node:1~writer', 'magnus-node:', 'magnus-node:a~b', 'host:node-1', 'ACTOR:lead',
    ])
      expect(parseAgentEntityValue(value), value).toBeNull();
  });

  it('accepts only agent identities as ingested agent entities', () => {
    expect(securityFusionEntityRefSchema.safeParse({ type: 'agent', value: 'actor:lead' }).success).toBe(true);
    expect(securityFusionEntityRefSchema.safeParse({ type: 'agent', value: 'agent-ref:node-1~lead' }).success).toBe(true);
    expect(securityFusionEntityRefSchema.safeParse({ type: 'agent', value: 'magnus-node:node-1' }).success).toBe(false);
    expect(securityFusionEntityRefSchema.safeParse({ type: 'agent', value: 'lead' }).success).toBe(false);
    // Other entity types keep their free-form values.
    expect(securityFusionEntityRefSchema.safeParse({ type: 'host', value: 'actor:anything at all' }).success).toBe(true);
  });

  it('validates the case entity filter', () => {
    expect(securityFusionCaseEntityFilterSchema.parse({ entityType: 'agent', entity: 'magnus-node:node-1' }))
      .toEqual({ entityType: 'agent', entity: 'magnus-node:node-1' });
    expect(securityFusionCaseEntityFilterSchema.parse({ entityType: 'host', entity: ' Web-1 ' }))
      .toEqual({ entityType: 'host', entity: 'Web-1' });
    for (const input of [
      { entityType: 'agent' },
      { entity: 'actor:lead' },
      { entityType: 'robot', entity: 'actor:lead' },
      { entityType: 'agent', entity: 'lead' },
      { entityType: 'host', entity: '' },
      { entityType: 'host', entity: 'x'.repeat(513) },
    ])
      expect(securityFusionCaseEntityFilterSchema.safeParse(input).success, JSON.stringify(input)).toBe(false);
  });
});
