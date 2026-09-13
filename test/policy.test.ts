import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { FastifyInstance } from "fastify";

const temp = mkdtempSync(join(tmpdir(), "gmail-proxy-test-"));
process.env.NODE_ENV = "test";
process.env.API_TOKEN = "api-test-token-long-enough";
process.env.ADMIN_TOKEN = "admin-test-token-long-enough";
process.env.ENCRYPTION_KEY = Buffer.alloc(32, 7).toString("base64");
process.env.DATABASE_PATH = join(temp, "test.sqlite");
process.env.LOG_LEVEL = "silent";

let app: FastifyInstance;

beforeAll(async () => {
  const { buildApp } = await import("../src/index.js");
  app = await buildApp();
});

afterAll(async () => {
  await app.close();
  rmSync(temp, { recursive: true, force: true });
});

describe("mailbox mutation policy", () => {
  it("allows user labels plus STARRED and IMPORTANT, but no state-changing system labels", async () => {
    const { isMutableLabel } = await import("../src/routes/gmail.js");
    expect(isMutableLabel({ id: "Label_123", type: "user" })).toBe(true);
    expect(isMutableLabel({ id: "STARRED", type: "system" })).toBe(true);
    expect(isMutableLabel({ id: "IMPORTANT", type: "system" })).toBe(true);
    for (const systemId of ["TRASH", "SPAM", "INBOX", "UNREAD", "SENT", "DRAFT"]) {
      expect(isMutableLabel({ id: systemId, type: "system" })).toBe(false);
    }
  });

  it("requires the API bearer token", async () => {
    const response = await app.inject({ method: "GET", url: "/gmail/v1/accounts" });
    expect(response.statusCode).toBe(401);
  });

  it("blocks unlisted mutations before contacting Google", async () => {
    const response = await app.inject({ method: "POST", url: "/gmail/v1/users/me/messages/send", headers: { authorization: "Bearer api-test-token-long-enough" }, payload: { raw: "abc" } });
    expect(response.statusCode).toBe(403);
    expect(response.json().error.status).toBe("PERMISSION_DENIED");
  });

  it("does not expose drafts through GET", async () => {
    const response = await app.inject({ method: "GET", url: "/gmail/v1/users/me/drafts", headers: { authorization: "Bearer api-test-token-long-enough" } });
    expect(response.statusCode).toBe(404);
  });
});
