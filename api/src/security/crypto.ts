import crypto, { CipherGCM, DecipherGCM } from "crypto";
import { promisify } from "util";

export function generateSalt() {
  return crypto.randomBytes(16);
}

export function deriveKey(masterKey: Buffer, salt: Buffer): Promise<Buffer> {
  const scrypt = promisify(crypto.scrypt);

  return scrypt(masterKey, salt, 32) as Promise<Buffer>;
}

export async function encrypt(masterKey: Buffer, data: string) {
  const salt = generateSalt();

  const entryKey = await deriveKey(masterKey, salt);

  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(
    "aes-256-gcm",
    entryKey,
    iv
  ) as CipherGCM;

  entryKey.fill(0);

  const encrypted = Buffer.concat([
    cipher.update(data, "utf8"),
    cipher.final(),
  ]);
  const tag = cipher.getAuthTag();

  const combined = Buffer.concat([salt, iv, encrypted, tag]);

  return combined.toString("base64");
}

export async function decrypt(masterKey: Buffer, encryptionMetadata: string) {
  const combined = Buffer.from(encryptionMetadata, "base64");

  const salt = combined.subarray(0, 16);
  const iv = combined.subarray(16, 28);
  const encrypted = combined.subarray(28, combined.length - 16);
  const tag = combined.subarray(combined.length - 16);

  const entryKey = await deriveKey(masterKey, salt);

  const decipher = crypto.createDecipheriv(
    "aes-256-gcm",
    entryKey,
    iv
  ) as DecipherGCM;

  entryKey.fill(0);

  decipher.setAuthTag(tag);

  const decrypted = Buffer.concat([
    decipher.update(encrypted),
    decipher.final(),
  ]);

  return decrypted.toString("utf8");
}
