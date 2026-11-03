import { defineConfig } from 'prisma/config';

export default defineConfig({
  schema: 'prisma/schema.prisma',
  datasource: {
    url: process.env['DATABASE_URL'] ?? 'postgresql://invalid:invalid@127.0.0.1:5432/cindertrace_build_only',
  },
});
