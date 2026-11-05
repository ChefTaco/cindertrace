import { z } from "zod";
/** Product-owned native browser authentication. Suite identity remains Oathweave-owned. */
export const localBrowserLoginSchema = z
  .object({
    username: z.string().min(1).max(256),
    password: z.string().min(1).max(4096),
  })
  .strict();
export const localBrowserProfileSchema = z.object({
  username: z.string(),
  userId: z.string(),
  role: z.enum(["ADMIN", "OPERATOR", "VIEWER"]),
  provider: z.literal("local"),
});
