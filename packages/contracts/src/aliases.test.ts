import { expect, it } from 'vitest';
import { canonicalSecuritySource, securityFusionSourceSchema } from './index.js';
it('accepts historical and public source names while retaining their exact wire identities', () => {
  for (const source of ['aegis_ui','security_console','cindertrace_ui','chattermost','mattermost']) expect(securityFusionSourceSchema.parse(source)).toBe(source);
  expect(canonicalSecuritySource('aegis_ui')).toBe('security_console');expect(canonicalSecuritySource('chattermost')).toBe('mattermost');
});
