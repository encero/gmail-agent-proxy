import type { FastifyInstance } from "fastify";
import { config } from "../config.js";
import type { Store } from "../db.js";
import type { CryptoBox } from "../crypto.js";
import { secretEquals } from "../crypto.js";
import { beginOAuth, finishOAuth, validateAndNormalizeClient } from "../google.js";
import { adminAuth } from "../auth.js";

const esc = (value: unknown): string => String(value).replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
const page = (title: string, body: string) => `<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${esc(title)}</title><style>body{font:16px system-ui;max-width:850px;margin:3rem auto;padding:0 1rem;color:#17202a}section{border:1px solid #d9dee3;border-radius:10px;padding:1rem;margin:1rem 0}input,textarea,button{font:inherit;padding:.55rem}textarea{width:100%;box-sizing:border-box}code{background:#f2f4f5;padding:.15rem .3rem}table{width:100%;border-collapse:collapse}td,th{text-align:left;border-bottom:1px solid #ddd;padding:.5rem}button{cursor:pointer}.danger{color:#a00}</style></head><body><h1>${esc(title)}</h1>${body}</body></html>`;

export async function adminRoutes(app: FastifyInstance, store: Store, box: CryptoBox): Promise<void> {
  const requireAdmin = adminAuth(config.adminToken, box);

  app.get("/admin/login", async (_request, reply) => reply.type("text/html").send(page("Gmail proxy admin", `<form method="post"><label>Admin token <input name="token" type="password" autofocus required></label> <button>Sign in</button></form>`)));
  app.post<{ Body: { token?: string } }>("/admin/login", async (request, reply) => {
    if (!secretEquals(request.body?.token, config.adminToken)) return reply.code(401).type("text/html").send(page("Sign-in failed", "<p>Invalid admin token.</p>"));
    return reply.setCookie("admin_session", box.sessionSignature(), { httpOnly: true, sameSite: "strict", secure: config.PUBLIC_BASE_URL.startsWith("https:"), path: "/admin", maxAge: 8 * 60 * 60 }).redirect("/admin");
  });

  app.get("/admin", { preHandler: requireAdmin }, async (_request, reply) => {
    const accounts = store.listAccounts();
    const rows = accounts.map((a) => `<tr><td>${esc(a.email)}</td><td><code>${esc(a.id)}</code></td><td><form method="post" action="/admin/accounts/${encodeURIComponent(a.id)}/delete"><button class="danger">Unlink</button></form></td></tr>`).join("");
    const clientReady = Boolean(store.getSecret("oauth_client"));
    return reply.type("text/html").send(page("Gmail agent proxy", `
      <p>OAuth callback URL: <code>${esc(config.oauthRedirectUri)}</code></p>
      <section><h2>1. Google OAuth client</h2><p>Create a Google OAuth client and add the callback URL above, then upload the downloaded JSON here. It is encrypted at rest.</p><form method="post" action="/admin/oauth-client" enctype="multipart/form-data"><input name="client_json" type="file" accept="application/json,.json" required> <button>Save client</button></form><p>Status: ${clientReady ? "configured" : "not configured"}</p></section>
      <section><h2>2. Linked accounts</h2><table><thead><tr><th>Email</th><th>Account selector</th><th></th></tr></thead><tbody>${rows || "<tr><td colspan=3>No accounts linked.</td></tr>"}</tbody></table>${clientReady ? '<p><a href="/admin/oauth/start">Link another Google account</a></p>' : ""}</section>
      <section><h2>Audit</h2><p><a href="/admin/audit">View recent metadata audit records</a></p></section>`));
  });

  app.post("/admin/oauth-client", { preHandler: requireAdmin }, async (request, reply) => {
    const upload = await request.file();
    if (!upload || upload.fieldname !== "client_json") return reply.code(400).send("A client_json file is required");
    const contents = (await upload.toBuffer()).toString("utf8");
    store.setSecret("oauth_client", validateAndNormalizeClient(contents));
    return reply.redirect("/admin");
  });
  app.get("/admin/oauth/start", { preHandler: requireAdmin }, async (_request, reply) => reply.redirect(beginOAuth(store, config.oauthRedirectUri)));
  app.get<{ Querystring: { code?: string; state?: string; error?: string } }>("/admin/oauth/callback", async (request, reply) => {
    if (request.query.error) return reply.code(400).type("text/html").send(page("Google authorization failed", `<p>${esc(request.query.error)}</p>`));
    if (!request.query.code || !request.query.state) return reply.code(400).send("Missing OAuth code or state");
    const account = await finishOAuth(store, config.oauthRedirectUri, request.query.code, request.query.state);
    return reply.type("text/html").send(page("Account linked", `<p>Linked ${esc(account.email)}.</p><p><a href="/admin">Return to admin</a></p>`));
  });
  app.post<{ Params: { id: string } }>("/admin/accounts/:id/delete", { preHandler: requireAdmin }, async (request, reply) => { store.deleteAccount(request.params.id); return reply.redirect("/admin"); });
  app.get("/admin/audit", { preHandler: requireAdmin }, async (_request, reply) => reply.send({ records: store.recentAudit(200) }));
}
