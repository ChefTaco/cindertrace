export type UserRole = "ADMIN" | "OPERATOR" | "VIEWER";
export type SecurityPermission =
  | "security-fusion:summary"
  | "security-fusion:read"
  | "security-fusion:evidence:read";
export interface AuthTokenPayload {
  userId: string;
  email: string;
  role: UserRole;
  iat: number;
  exp: number;
  /** When the person last proved their credentials (ms since epoch), where known. */
  authenticatedAt?: number;
}
export type AppVariables = { Variables: { user: AuthTokenPayload } };
export type AuditAction = string;
export interface ApiError {
  success: false;
  error: { code: string; message: string };
}
