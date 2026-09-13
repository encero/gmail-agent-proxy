import type { FastifyInstance, FastifyReply, FastifyRequest } from "fastify";
import { z } from "zod";
import type { Account, Store } from "../db.js";
import { gmailRequest } from "../google.js";

const id = z.string().min(1).max(500).regex(/^[A-Za-z0-9_@.+=-]+$/);
const listQuery = z.object({
  maxResults: z.coerce.number().int().min(1).max(500).optional(),
  pageToken: z.string().max(4096).optional(),
  q: z.string().max(2048).optional(),
  labelIds: z.union([z.string(), z.array(z.string())]).optional(),
  includeSpamTrash: z.enum(["true", "false"]).optional()
});
const modifyBody = z.object({ addLabelIds: z.array(id).max(100).default([]), removeLabelIds: z.array(id).max(100).default([]) }).strict();
const batchModifyBody = modifyBody.extend({ ids: z.array(id).min(1).max(1000) });
const labelBody = z.object({ name: z.string().min(1).max(225), labelListVisibility: z.enum(["labelShow", "labelShowIfUnread", "labelHide"]).optional(), messageListVisibility: z.enum(["show", "hide"]).optional(), color: z.object({ textColor: z.string(), backgroundColor: z.string() }).optional() }).strict();
const SAFE_SYSTEM_LABELS = new Set(["STARRED", "IMPORTANT"]);

export function isMutableLabel(label: { id: string; type: "system" | "user" }): boolean {
  return label.type === "user" || SAFE_SYSTEM_LABELS.has(label.id);
}

function googleQuery(input: Record<string, unknown>, keys: string[]): URLSearchParams {
  const output = new URLSearchParams();
  for (const key of keys) {
    const values = Array.isArray(input[key]) ? input[key] as unknown[] : [input[key]];
    for (const value of values) if (value !== undefined) output.append(key, String(value));
  }
  return output;
}

function resolve(store: Store, selector: string): Account {
  const account = store.getAccount(selector);
  if (!account) throw Object.assign(new Error(selector === "me" ? "The 'me' selector requires exactly one linked account" : "Linked account not found"), { statusCode: 404 });
  return account;
}

async function validateLabels(store: Store, account: Account, ids: string[]): Promise<void> {
  if (!ids.length) return;
  const result = await gmailRequest(store, account, "/users/me/labels") as { labels?: Array<{ id: string; type: "system" | "user" }> };
  const labels = new Map((result.labels ?? []).map((label) => [label.id, label]));
  for (const labelId of ids) {
    const label = labels.get(labelId);
    if (!label) throw Object.assign(new Error(`Unknown label ID: ${labelId}`), { statusCode: 400 });
    if (!isMutableLabel(label)) throw Object.assign(new Error(`System label ${label.id} is blocked by policy`), { statusCode: 403 });
  }
}

async function requireUserLabel(store: Store, account: Account, labelId: string): Promise<void> {
  const label = await gmailRequest(store, account, `/users/me/labels/${encodeURIComponent(labelId)}`) as { type?: string };
  if (label.type !== "user") throw Object.assign(new Error("System labels cannot be updated or deleted"), { statusCode: 403 });
}

export async function gmailRoutes(app: FastifyInstance, store: Store, apiPreHandler: (request: FastifyRequest, reply: FastifyReply) => Promise<void>): Promise<void> {
  app.addHook("preHandler", apiPreHandler);
  const audited = async (request: FastifyRequest, reply: FastifyReply, account: Account | undefined, resourceIds: string[], operation: () => Promise<unknown>) => {
    try {
      const result = await operation();
      store.audit({ actor: "api-token", accountId: account?.id, method: request.method, endpoint: request.routeOptions.url ?? request.url, resourceIds, outcome: "allowed", statusCode: reply.statusCode });
      return result;
    } catch (error) {
      const status = typeof error === "object" && error && "statusCode" in error ? Number((error as { statusCode: number }).statusCode) : 500;
      store.audit({ actor: "api-token", accountId: account?.id, method: request.method, endpoint: request.routeOptions.url ?? request.url, resourceIds, outcome: status === 403 ? "blocked" : "error", statusCode: status });
      throw error;
    }
  };

  app.get("/accounts", async (request, reply) => audited(request, reply, undefined, [], async () => ({ accounts: store.listAccounts() })));

  app.get<{ Querystring: Record<string, unknown> }>("/accounts/-/messages", async (request, reply) => {
    const query = listQuery.parse(request.query);
    return audited(request, reply, undefined, [], async () => {
      const accounts = store.listAccounts();
      const wanted = query.maxResults ?? 100;
      const perAccount = Math.max(1, Math.ceil(wanted / Math.max(accounts.length, 1)));
      let cursors: Record<string, string | null> | undefined;
      if (query.pageToken) {
        try {
          const decoded = JSON.parse(Buffer.from(query.pageToken, "base64url").toString("utf8"));
          cursors = z.object({ v: z.literal(1), cursors: z.record(z.string(), z.string().max(4096).nullable()) }).parse(decoded).cursors;
        }
        catch { throw Object.assign(new Error("Invalid aggregate pageToken"), { statusCode: 400 }); }
      }
      const results = await Promise.all(accounts.map(async (summary) => {
        const account = resolve(store, summary.id);
        if (cursors?.[account.id] === null) return { account, result: {} as { messages?: Array<Record<string, unknown>>; nextPageToken?: string; resultSizeEstimate?: number } };
        const accountQuery = { ...query, maxResults: perAccount, pageToken: cursors?.[account.id] ?? undefined };
        const result = await gmailRequest(store, account, "/users/me/messages", { query: googleQuery(accountQuery, ["maxResults", "pageToken", "q", "labelIds", "includeSpamTrash"]) }) as { messages?: Array<Record<string, unknown>>; nextPageToken?: string; resultSizeEstimate?: number };
        return { account, result };
      }));
      const nextCursors = Object.fromEntries(results.map(({ account, result }) => [account.id, result.nextPageToken ?? null]));
      const messages = results.flatMap(({ account, result }) => (result.messages ?? []).map((message) => ({ ...message, accountId: account.id, accountEmail: account.email })));
      const hasNextPage = Object.values(nextCursors).some((cursor) => cursor !== null);
      return { messages, resultSizeEstimate: results.reduce((sum, { result }) => sum + (result.resultSizeEstimate ?? 0), 0), ...(hasNextPage ? { nextPageToken: Buffer.from(JSON.stringify({ v: 1, cursors: nextCursors })).toString("base64url") } : {}) };
    });
  });

  app.get<{ Params: { userId: string } }>("/users/:userId/profile", async (request, reply) => {
    const account = resolve(store, request.params.userId);
    return audited(request, reply, account, [], () => gmailRequest(store, account, "/users/me/profile"));
  });
  app.get<{ Params: { userId: string }; Querystring: Record<string, unknown> }>("/users/:userId/messages", async (request, reply) => {
    const account = resolve(store, request.params.userId); const query = listQuery.parse(request.query);
    return audited(request, reply, account, [], () => gmailRequest(store, account, "/users/me/messages", { query: googleQuery(query, ["maxResults", "pageToken", "q", "labelIds", "includeSpamTrash"]) }));
  });
  app.get<{ Params: { userId: string; id: string }; Querystring: Record<string, unknown> }>("/users/:userId/messages/:id", async (request, reply) => {
    const account = resolve(store, request.params.userId); const messageId = id.parse(request.params.id);
    const format = z.enum(["minimal", "full", "raw", "metadata"]).default("full").parse(request.query.format);
    const metadataHeaders = z.union([z.string(), z.array(z.string())]).optional().parse(request.query.metadataHeaders);
    const query = googleQuery({ format, metadataHeaders }, ["format", "metadataHeaders"]);
    return audited(request, reply, account, [messageId], () => gmailRequest(store, account, `/users/me/messages/${encodeURIComponent(messageId)}`, { query }));
  });
  app.get<{ Params: { userId: string; messageId: string; id: string } }>("/users/:userId/messages/:messageId/attachments/:id", async (request, reply) => {
    const account = resolve(store, request.params.userId); const messageId = id.parse(request.params.messageId); const attachmentId = id.parse(request.params.id);
    return audited(request, reply, account, [messageId, attachmentId], () => gmailRequest(store, account, `/users/me/messages/${encodeURIComponent(messageId)}/attachments/${encodeURIComponent(attachmentId)}`));
  });
  app.post<{ Params: { userId: string; id: string }; Body: unknown }>("/users/:userId/messages/:id/modify", async (request, reply) => {
    const account = resolve(store, request.params.userId); const messageId = id.parse(request.params.id); const body = modifyBody.parse(request.body);
    return audited(request, reply, account, [messageId], async () => { await validateLabels(store, account, [...body.addLabelIds, ...body.removeLabelIds]); return gmailRequest(store, account, `/users/me/messages/${encodeURIComponent(messageId)}/modify`, { method: "POST", body }); });
  });
  app.post<{ Params: { userId: string }; Body: unknown }>("/users/:userId/messages/batchModify", async (request, reply) => {
    const account = resolve(store, request.params.userId); const body = batchModifyBody.parse(request.body);
    return audited(request, reply, account, body.ids, async () => { await validateLabels(store, account, [...body.addLabelIds, ...body.removeLabelIds]); return gmailRequest(store, account, "/users/me/messages/batchModify", { method: "POST", body }); });
  });

  app.get<{ Params: { userId: string }; Querystring: Record<string, unknown> }>("/users/:userId/threads", async (request, reply) => {
    const account = resolve(store, request.params.userId); const query = listQuery.parse(request.query);
    return audited(request, reply, account, [], () => gmailRequest(store, account, "/users/me/threads", { query: googleQuery(query, ["maxResults", "pageToken", "q", "labelIds", "includeSpamTrash"]) }));
  });
  app.get<{ Params: { userId: string; id: string }; Querystring: Record<string, unknown> }>("/users/:userId/threads/:id", async (request, reply) => {
    const account = resolve(store, request.params.userId); const threadId = id.parse(request.params.id);
    const format = z.enum(["minimal", "full", "metadata"]).default("full").parse(request.query.format);
    return audited(request, reply, account, [threadId], () => gmailRequest(store, account, `/users/me/threads/${encodeURIComponent(threadId)}`, { query: googleQuery({ format, metadataHeaders: request.query.metadataHeaders }, ["format", "metadataHeaders"]) }));
  });
  app.post<{ Params: { userId: string; id: string }; Body: unknown }>("/users/:userId/threads/:id/modify", async (request, reply) => {
    const account = resolve(store, request.params.userId); const threadId = id.parse(request.params.id); const body = modifyBody.parse(request.body);
    return audited(request, reply, account, [threadId], async () => { await validateLabels(store, account, [...body.addLabelIds, ...body.removeLabelIds]); return gmailRequest(store, account, `/users/me/threads/${encodeURIComponent(threadId)}/modify`, { method: "POST", body }); });
  });

  app.get<{ Params: { userId: string } }>("/users/:userId/labels", async (request, reply) => { const account = resolve(store, request.params.userId); return audited(request, reply, account, [], () => gmailRequest(store, account, "/users/me/labels")); });
  app.get<{ Params: { userId: string; id: string } }>("/users/:userId/labels/:id", async (request, reply) => { const account = resolve(store, request.params.userId); const labelId = id.parse(request.params.id); return audited(request, reply, account, [labelId], () => gmailRequest(store, account, `/users/me/labels/${encodeURIComponent(labelId)}`)); });
  app.post<{ Params: { userId: string }; Body: unknown }>("/users/:userId/labels", async (request, reply) => { const account = resolve(store, request.params.userId); const body = labelBody.parse(request.body); return audited(request, reply, account, [], () => gmailRequest(store, account, "/users/me/labels", { method: "POST", body })); });
  app.patch<{ Params: { userId: string; id: string }; Body: unknown }>("/users/:userId/labels/:id", async (request, reply) => { const account = resolve(store, request.params.userId); const labelId = id.parse(request.params.id); const body = labelBody.partial().parse(request.body); return audited(request, reply, account, [labelId], async () => { await requireUserLabel(store, account, labelId); return gmailRequest(store, account, `/users/me/labels/${encodeURIComponent(labelId)}`, { method: "PATCH", body }); }); });
  app.delete<{ Params: { userId: string; id: string } }>("/users/:userId/labels/:id", async (request, reply) => { const account = resolve(store, request.params.userId); const labelId = id.parse(request.params.id); return audited(request, reply, account, [labelId], async () => { await requireUserLabel(store, account, labelId); return gmailRequest(store, account, `/users/me/labels/${encodeURIComponent(labelId)}`, { method: "DELETE" }); }); });

  app.route({ method: ["POST", "PUT", "PATCH", "DELETE"], url: "/*", handler: async (request, reply) => {
    store.audit({ actor: "api-token", method: request.method, endpoint: request.url.split("?")[0]!, outcome: "blocked", statusCode: 403 });
    return reply.code(403).send({ error: { code: 403, message: "This mutation is not in the proxy allowlist", status: "PERMISSION_DENIED" } });
  } });
}
