import { afterEach, expect, it, vi } from 'vitest';
import { getSecretKey } from './auth-constants';
afterEach(()=>vi.unstubAllEnvs());
it('refuses short browser signing keys',()=>{vi.stubEnv('SESSION_SECRET','short-fixture');expect(()=>getSecretKey()).toThrow(/32/);});
