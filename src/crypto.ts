import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

function decodeKey(value: string): Buffer {
  const key = /^[a-f\d]{64}$/i.test(value) ? Buffer.from(value, "hex") : Buffer.from(value, "base64");
  if (key.length !== 32) throw new Error("ENCRYPTION_KEY must be exactly 32 bytes encoded as base64 or 64 hex characters");
  return key;
}

export class CryptoBox {
  private readonly key: Buffer;

  constructor(encodedKey: string) {
    this.key = decodeKey(encodedKey);
  }

  seal(value: string): string {
    const iv = randomBytes(12);
    const cipher = createCipheriv("aes-256-gcm", this.key, iv);
    const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), encrypted]).toString("base64url");
  }

  open(value: string): string {
    const packed = Buffer.from(value, "base64url");
    if (packed.length < 29) throw new Error("Invalid encrypted value");
    const decipher = createDecipheriv("aes-256-gcm", this.key, packed.subarray(0, 12));
    decipher.setAuthTag(packed.subarray(12, 28));
    return Buffer.concat([decipher.update(packed.subarray(28)), decipher.final()]).toString("utf8");
  }

  sessionSignature(): string {
    return createHmac("sha256", this.key).update("gmail-agent-proxy:admin-session:v1").digest("base64url");
  }
}

export function stableId(value: string): string {
  return createHash("sha256").update(value.toLowerCase()).digest("base64url").slice(0, 22);
}

export function secretEquals(actual: string | undefined, expected: string): boolean {
  if (!actual) return false;
  const left = Buffer.from(actual);
  const right = Buffer.from(expected);
  return left.length === right.length && timingSafeEqual(left, right);
}
