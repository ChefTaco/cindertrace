/** Strip IPv6-mapped IPv4 prefix and normalize empty values. */
export function normalizeIpAddress(rawIp: string | null | undefined): string {
  if (!rawIp) return "";
  const trimmed = rawIp.trim();
  return trimmed.startsWith("::ffff:") ? trimmed.slice(7) : trimmed;
}
