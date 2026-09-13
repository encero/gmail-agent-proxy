import Fastify from "fastify";
import cookie from "@fastify/cookie";
import formbody from "@fastify/formbody";
import helmet from "@fastify/helmet";
import multipart from "@fastify/multipart";
import rateLimit from "@fastify/rate-limit";
import { ZodError } from "zod";
import { config } from "./config.js";
import { CryptoBox } from "./crypto.js";
import { Store } from "./db.js";
import { GoogleError } from "./google.js";
import { apiAuth } from "./auth.js";
import { adminRoutes } from "./routes/admin.js";
import { gmailRoutes } from "./routes/gmail.js";

export async function buildApp() {
  const app = Fastify({ logger: { level: config.LOG_LEVEL }, bodyLimit: 1024 * 1024, trustProxy: false });
  const box = new CryptoBox(config.encryptionKey);
  const store = new Store(config.DATABASE_PATH, box);
  await app.register(cookie);
  await app.register(formbody);
  await app.register(multipart, { limits: { files: 1, fileSize: 64 * 1024, fields: 0 } });
  await app.register(helmet, { contentSecurityPolicy: { directives: { defaultSrc: ["'self'"], styleSrc: ["'unsafe-inline'"] } } });
  await app.register(rateLimit, { max: 300, timeWindow: "1 minute" });
  app.get("/healthz", async () => ({ status: "ok" }));
  await adminRoutes(app, store, box);
  await app.register(async (scope) => gmailRoutes(scope, store, apiAuth(config.apiToken)), { prefix: "/gmail/v1" });
  app.setErrorHandler((error, _request, reply) => {
    if (error instanceof GoogleError) return reply.code(error.statusCode).send(error.payload);
    if (error instanceof ZodError) return reply.code(400).send({ error: { code: 400, message: "Invalid request", status: "INVALID_ARGUMENT", details: error.issues } });
    const normalized = error instanceof Error ? error : new Error("Unknown error");
    const statusCode = "statusCode" in normalized && typeof normalized.statusCode === "number" ? normalized.statusCode : 500;
    if (statusCode >= 500) app.log.error(error);
    return reply.code(statusCode).send({ error: { code: statusCode, message: statusCode >= 500 ? "Internal proxy error" : normalized.message, status: statusCode === 403 ? "PERMISSION_DENIED" : "ERROR" } });
  });
  store.purgeAudit(config.AUDIT_RETENTION_DAYS);
  const purgeTimer = setInterval(() => store.purgeAudit(config.AUDIT_RETENTION_DAYS), 24 * 60 * 60_000);
  purgeTimer.unref();
  app.addHook("onClose", async () => { clearInterval(purgeTimer); store.db.close(); });
  return app;
}

if (process.env.NODE_ENV !== "test") {
  const app = await buildApp();
  await app.listen({ host: config.HOST, port: config.PORT });
}
