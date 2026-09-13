import type { FastifyReply, FastifyRequest } from "fastify";
import type { CryptoBox } from "./crypto.js";
import { secretEquals } from "./crypto.js";

function bearer(request: FastifyRequest): string | undefined {
  const header = request.headers.authorization;
  return header?.startsWith("Bearer ") ? header.slice(7) : undefined;
}

export function apiAuth(expected: string) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    if (!secretEquals(bearer(request), expected)) await reply.code(401).header("www-authenticate", "Bearer").send({ error: { code: 401, message: "Valid API bearer token required", status: "UNAUTHENTICATED" } });
  };
}

export function adminAuth(expected: string, box: CryptoBox) {
  return async (request: FastifyRequest, reply: FastifyReply): Promise<void> => {
    const valid = secretEquals(bearer(request), expected) || secretEquals(request.cookies.admin_session, box.sessionSignature());
    if (!valid) await reply.redirect("/admin/login");
  };
}
