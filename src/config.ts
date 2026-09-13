import { readFileSync } from "node:fs";
import { z } from "zod";

function secret(name: string, fallbackFile?: string): string {
  const direct = process.env[name];
  if (direct) return direct.trim();
  const file = process.env[`${name}_FILE`] ?? fallbackFile;
  if (!file) throw new Error(`${name} or ${name}_FILE is required`);
  return readFileSync(file, "utf8").trim();
}

const envSchema = z.object({
  HOST: z.string().default("0.0.0.0"),
  PORT: z.coerce.number().int().min(1).max(65535).default(3000),
  DATABASE_PATH: z.string().default("./data/proxy.sqlite"),
  PUBLIC_BASE_URL: z.string().url().default("http://127.0.0.1:3000"),
  AUDIT_RETENTION_DAYS: z.coerce.number().int().min(1).default(90),
  LOG_LEVEL: z.enum(["fatal", "error", "warn", "info", "debug", "trace", "silent"]).default("info")
});

const env = envSchema.parse(process.env);

export const config = {
  ...env,
  apiToken: secret("API_TOKEN", "/run/secrets/api_token"),
  adminToken: secret("ADMIN_TOKEN", "/run/secrets/admin_token"),
  encryptionKey: secret("ENCRYPTION_KEY", "/run/secrets/encryption_key"),
  oauthRedirectUri: new URL("/admin/oauth/callback", env.PUBLIC_BASE_URL).toString()
};
