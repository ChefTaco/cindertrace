import { expect, it } from 'vitest';
import { decodeRouteSegment } from './route-segment';
it('normalizes escaped lab identities once without changing historical identity bytes', () => {
  expect(decodeRouteSegment('lab-case%3Afixture')).toBe('lab-case:fixture');
  expect(decodeRouteSegment('case-fixture')).toBe('case-fixture');
  expect(decodeRouteSegment('literal%253Afixture')).toBe('literal%3Afixture');
});
it.each(['%2Fadmin', '%5Cadmin', '%2e%2e', '%00', '%', ''])('rejects invalid segment %s before proxy encoding', segment => {
  expect(() => decodeRouteSegment(segment)).toThrow();
});
