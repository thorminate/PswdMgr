import jwt, { JwtPayload } from "jsonwebtoken";
import bcrypt from "bcrypt";
import { NextFunction, Request, Response } from "express";
import * as clack from "@clack/prompts";
import { yellow } from "ansis";
import TokenBlacklist from "../models/TokenBlacklist.js";
import { randomUUID } from "node:crypto";
import { appendFile } from "node:fs/promises";

function getMASTER_HASH() {
  return ("$2b$13$" + process.env.MASTER_HASH).trim();
}

function getJWT_SECRET() {
  if (process.env.JWT_SECRET) {
    return process.env.JWT_SECRET;
  }

  const newSecret = randomUUID();
  process.env.JWT_SECRET = newSecret;
  appendFile("./.env", `\nJWT_SECRET="${newSecret}"`);

  return newSecret;
}

export async function verifyPassword(password: string) {
  const MASTER_HASH = getMASTER_HASH();

  if (!MASTER_HASH) {
    return false;
  }

  return await bcrypt.compare(password, MASTER_HASH);
}

export function generateToken(ip: string) {
  const SECRET = getJWT_SECRET();

  return jwt.sign({ iss: ip, jti: randomUUID() }, SECRET, { expiresIn: "1h" });
}

export function verifyToken(token: string, ip: string): boolean {
  const SECRET = getJWT_SECRET();

  try {
    const decoded = jwt.verify(token, SECRET);
    if (!decoded) {
      return false;
    }
    if (typeof decoded !== "object") {
      return false;
    }
    if (!decoded.iss) {
      return false;
    }
    return decoded.iss === ip;
  } catch (e) {
    clack.log.warn(yellow`Failed token auth attempt from ${ip}`);
    return false;
  }
}

export function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      res.status(401).json({ error: "Token invalid" });
      clack.log.warn(yellow`Failed token auth attempt from ${req.ip}`);
      return;
    }

    const ip = req.ip;
    if (!ip) {
      res.status(401).json({ error: "Token invalid" });
      clack.log.warn(yellow`Failed token auth attempt from ${req.ip}`);
      return;
    }

    const isValid = verifyToken(token, ip);

    if (!isValid) {
      res.status(401).json({ error: "Token invalid" });
      clack.log.warn(yellow`Failed token auth attempt from ${req.ip}`);
      return;
    }

    next();
  } catch (error) {
    res.status(401).json({ error: "Token invalid" });
    clack.log.warn(yellow`Failed token auth attempt from ${req.ip}`);
    return;
  }
}

export async function blacklistMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    res.status(401).json({ error: "Token invalid" });
    clack.log.warn(yellow`Failed token auth attempt from ${req.ip}`);
    return;
  }

  try {
    const { jti } = jwt.verify(token, getJWT_SECRET()) as JwtPayload;

    const blacklisted = await TokenBlacklist.findOne({ jti });

    if (blacklisted) {
      res.status(401).json({ error: "Token invalid" });
      clack.log.warn(yellow`Failed token auth attempt from ${req.ip}`);
      return;
    }
  } catch (e) {
    res.status(401).json({ error: "Token invalid" });
    clack.log.warn(yellow`Failed token auth attempt from ${req.ip}`);
    return;
  }

  next();
}
