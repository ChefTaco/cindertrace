import { constants } from "node:fs";
import { open, mkdir, lstat, link, unlink } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { createHash, randomUUID } from "node:crypto";
import { hash, verify, argon2id } from "argon2";
import { z } from "zod";
const Input = z
  .object({
    username: z.string().min(1).max(256),
    password: z
      .string()
      .min(12)
      .max(4096)
      .refine((value) => !value.includes("\0")),
  })
  .strict();
const Output = z
  .object({
    schema: z.literal(1),
    username: z.string(),
    passwordHash: z.string().startsWith("$argon2id$"),
    sourceSha256: z.string().regex(/^[a-f0-9]{64}$/),
  })
  .strict();
async function protectedFile(path: string): Promise<Buffer> {
  const file = await open(path, constants.O_RDONLY | constants.O_NOFOLLOW);
  try {
    const info = await file.stat();
    if (
      !info.isFile() ||
      (info.mode & 0o077) !== 0 ||
      info.uid !== process.geteuid?.() ||
      info.size > 32768
    )
      throw Error("Invalid protected file");
    return await file.readFile();
  } finally {
    await file.close();
  }
}
/** Fresh initialization only. Existing output is verified, never replaced or rehashed. */
export async function prepareBrowserCredentials(
  configPath: string,
  outputPath: string,
): Promise<void> {
  process.umask(0o077);
  const bytes = await protectedFile(configPath),
    input = Input.parse(JSON.parse(bytes.toString("utf8"))),
    sourceSha256 = createHash("sha256").update(bytes).digest("hex");
  const destination = resolve(outputPath),
    directory = dirname(destination);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const parent = await lstat(directory);
  if (
    !parent.isDirectory() ||
    parent.isSymbolicLink() ||
    (parent.mode & 0o077) !== 0 ||
    parent.uid !== process.geteuid?.()
  )
    throw Error("Invalid protected output directory");
  async function existing(): Promise<boolean> {
    try {
      const result = Output.parse(
        JSON.parse((await protectedFile(destination)).toString("utf8")),
      );
      if (
        result.sourceSha256 !== sourceSha256 ||
        result.username !== input.username ||
        !(await verify(result.passwordHash, input.password))
      )
        throw Error("Existing credential output differs");
      return true;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "ENOENT") return false;
      throw error;
    }
  }
  if (await existing()) return;
  const result = Output.parse({
    schema: 1,
    username: input.username,
    sourceSha256,
    passwordHash: await hash(input.password, {
      type: argon2id,
      memoryCost: 65536,
      timeCost: 3,
      parallelism: 1,
    }),
  });
  const temporary = destination + ".pending-" + randomUUID();
  const file = await open(temporary, "wx", 0o600);
  try {
    await file.writeFile(JSON.stringify(result) + "\n");
    await file.sync();
  } finally {
    await file.close();
  }
  try {
    try {
      await link(temporary, destination);
    } catch (error) {
      if (
        (error as NodeJS.ErrnoException).code !== "EEXIST" ||
        !(await existing())
      )
        throw error;
    }
    const folder = await open(directory, "r");
    try {
      await folder.sync();
    } finally {
      await folder.close();
    }
  } finally {
    await unlink(temporary);
  }
}
if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  const args = process.argv.slice(2);
  if (args.length !== 4 || args[0] !== "--config" || args[2] !== "--output") {
    console.error(
      "Usage: hash-password --config PROTECTED_JSON --output PROTECTED_JSON",
    );
    process.exitCode = 2;
  } else
    await prepareBrowserCredentials(args[1]!, args[3]!).catch(() => {
      console.error(
        "Unable to prepare protected browser credentials; existing credentials were preserved.",
      );
      process.exitCode = 1;
    });
}
