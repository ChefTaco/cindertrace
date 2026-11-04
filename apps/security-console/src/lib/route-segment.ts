/** Next route parameters may retain URL escapes; normalize exactly once at ingress. */
export function decodeRouteSegment(segment: string): string {
  const decoded = decodeURIComponent(segment);
  if (!decoded || decoded === '.' || decoded === '..' || /[\/\\\0]/.test(decoded)) throw new Error('Invalid route segment');
  return decoded;
}
