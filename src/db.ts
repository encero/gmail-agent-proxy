import Database from "better-sqlite3";
import { mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { randomBytes, createHash } from "node:crypto";
import type { CryptoBox } from "./crypto.js";

export interface Account {
  id: string;
  email: string;
  refreshToken: string;
  scopes: string;
  createdAt: string;
  updatedAt: string;
}

interface AccountRow {
  id: string;
  email: string;
  refresh_token: string;
  scopes: string;
  created_at: string;
  updated_at: string;
}

export class Store {
  readonly db: Database.Database;
  constructor(path: string, private readonly box: CryptoBox) {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    this.db = new Database(path);
    this.db.pragma("journal_mode = WAL");
    this.db.pragma("foreign_keys = ON");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        encrypted_value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY,
        email TEXT NOT NULL UNIQUE,
        refresh_token TEXT NOT NULL,
        scopes TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS oauth_states (
        state_hash TEXT PRIMARY KEY,
        verifier_encrypted TEXT NOT NULL,
        expires_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS audit_log (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        occurred_at TEXT NOT NULL,
        actor TEXT NOT NULL,
        account_id TEXT,
        method TEXT NOT NULL,
        endpoint TEXT NOT NULL,
        resource_ids TEXT,
        outcome TEXT NOT NULL,
        status_code INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS audit_occurred_idx ON audit_log(occurred_at);
    `);
  }

  setSecret(key: string, value: string): void {
    this.db.prepare(`INSERT INTO settings(key, encrypted_value, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET encrypted_value=excluded.encrypted_value, updated_at=excluded.updated_at`)
      .run(key, this.box.seal(value), new Date().toISOString());
  }

  getSecret(key: string): string | undefined {
    const row = this.db.prepare("SELECT encrypted_value FROM settings WHERE key=?").get(key) as { encrypted_value: string } | undefined;
    return row ? this.box.open(row.encrypted_value) : undefined;
  }

  listAccounts(): Omit<Account, "refreshToken">[] {
    return (this.db.prepare("SELECT id,email,scopes,created_at,updated_at FROM accounts ORDER BY email").all() as Omit<AccountRow, "refresh_token">[])
      .map((r) => ({ id: r.id, email: r.email, scopes: r.scopes, createdAt: r.created_at, updatedAt: r.updated_at }));
  }

  getAccount(selector: string): Account | undefined {
    let row: AccountRow | undefined;
    if (selector === "me") {
      const rows = this.db.prepare("SELECT * FROM accounts LIMIT 2").all() as AccountRow[];
      if (rows.length !== 1) return undefined;
      row = rows[0];
    } else {
      row = this.db.prepare("SELECT * FROM accounts WHERE id=? OR lower(email)=lower(?)").get(selector, selector) as AccountRow | undefined;
    }
    return row && this.toAccount(row);
  }

  upsertAccount(id: string, email: string, refreshToken: string, scopes: string): void {
    const now = new Date().toISOString();
    this.db.prepare(`INSERT INTO accounts(id,email,refresh_token,scopes,created_at,updated_at) VALUES(?,?,?,?,?,?)
      ON CONFLICT(email) DO UPDATE SET id=excluded.id, refresh_token=excluded.refresh_token,
      scopes=excluded.scopes, updated_at=excluded.updated_at`)
      .run(id, email, this.box.seal(refreshToken), scopes, now, now);
  }

  deleteAccount(id: string): boolean {
    return this.db.prepare("DELETE FROM accounts WHERE id=?").run(id).changes > 0;
  }

  createOauthState(verifier: string): string {
    const state = randomBytes(32).toString("base64url");
    const hash = createHash("sha256").update(state).digest("hex");
    this.db.prepare("INSERT INTO oauth_states(state_hash,verifier_encrypted,expires_at) VALUES(?,?,?)")
      .run(hash, this.box.seal(verifier), new Date(Date.now() + 10 * 60_000).toISOString());
    return state;
  }

  consumeOauthState(state: string): string | undefined {
    const hash = createHash("sha256").update(state).digest("hex");
    const tx = this.db.transaction(() => {
      const row = this.db.prepare("SELECT verifier_encrypted,expires_at FROM oauth_states WHERE state_hash=?").get(hash) as { verifier_encrypted: string; expires_at: string } | undefined;
      this.db.prepare("DELETE FROM oauth_states WHERE state_hash=?").run(hash);
      if (!row || Date.parse(row.expires_at) < Date.now()) return undefined;
      return this.box.open(row.verifier_encrypted);
    });
    return tx();
  }

  audit(entry: { actor: string; accountId?: string; method: string; endpoint: string; resourceIds?: string[]; outcome: string; statusCode: number }): void {
    this.db.prepare(`INSERT INTO audit_log(occurred_at,actor,account_id,method,endpoint,resource_ids,outcome,status_code)
      VALUES(?,?,?,?,?,?,?,?)`).run(new Date().toISOString(), entry.actor, entry.accountId ?? null, entry.method,
      entry.endpoint, entry.resourceIds ? JSON.stringify(entry.resourceIds) : null, entry.outcome, entry.statusCode);
  }

  recentAudit(limit = 100): unknown[] {
    return this.db.prepare("SELECT * FROM audit_log ORDER BY id DESC LIMIT ?").all(Math.min(limit, 500));
  }

  purgeAudit(days: number): number {
    const cutoff = new Date(Date.now() - days * 86_400_000).toISOString();
    this.db.prepare("DELETE FROM oauth_states WHERE expires_at < ?").run(new Date().toISOString());
    return this.db.prepare("DELETE FROM audit_log WHERE occurred_at < ?").run(cutoff).changes;
  }

  private toAccount(row: AccountRow): Account {
    return { id: row.id, email: row.email, refreshToken: this.box.open(row.refresh_token), scopes: row.scopes, createdAt: row.created_at, updatedAt: row.updated_at };
  }
}
