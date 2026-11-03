import { PrismaClient } from "./generated/prisma/client.js";
import { PrismaPg } from "@prisma/adapter-pg";


let prisma: PrismaClient | undefined;

/** Singleton Prisma client — reuses connection across hot-reloads in dev. */
export function getDb(): PrismaClient {
  if (!prisma) {
    const connectionString = process.env["DATABASE_URL"];
    if (!connectionString) throw new Error("Security Fusion DATABASE_URL is required");
    const adapter = new PrismaPg({
      connectionString,
      connectionTimeoutMillis: 5_000,
      idleTimeoutMillis: 30_000,
      max: Number(process.env["DATABASE_POOL_SIZE"] ?? 20),
    });
    prisma = new PrismaClient({
      adapter,
      log:
        process.env["NODE_ENV"] === "development"
          ? ["query", "warn", "error"]
          : ["warn", "error"],
    });
  }
  return prisma;
}

export async function disconnectDb(): Promise<void> {
  if (prisma) {
    await prisma.$disconnect();
    prisma = undefined;
  }
}

export { PrismaClient };
