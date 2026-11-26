import { z } from "zod";
/** Product-owned native browser authentication. Suite identity remains Oathweave-owned. */
export const localBrowserLoginSchema = z
  .object({
    username: z.string().min(1).max(256),
    password: z.string().min(1).max(4096),
    /** The authenticator code, for an account with TOTP; asked for by a 401 with totpRequired. */
    totp: z.string().regex(/^\d{6}$/).optional(),
  })
  .strict();
export const localBrowserProfileSchema = z.object({
  username: z.string(),
  userId: z.string(),
  role: z.enum(["ADMIN", "OPERATOR", "VIEWER"]),
  provider: z.enum(["local", "oathweave"]),
});
