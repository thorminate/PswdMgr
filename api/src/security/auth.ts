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

function getTOKEN_SECRET() {
  if (process.env.TOKEN_SECRET) {
    return process.env.TOKEN_SECRET;
  }

  const newSecret = randomUUID();
  process.env.TOKEN_SECRET = newSecret;
  appendFile("./.env", `\nTOKEN_SECRET="${newSecret}"`);

  return newSecret;
}

function getREFRESH_SECRET() {
  if (process.env.REFRESH_SECRET) {
    return process.env.REFRESH_SECRET;
  }

  const newSecret = randomUUID();
  process.env.REFRESH_SECRET = newSecret;
  appendFile("./.env", `\nREFRESH_SECRET="${newSecret}"`);

  return newSecret;
}

export async function verifyPassword(password: string) {
  const MASTER_HASH = getMASTER_HASH();

  if (!MASTER_HASH) {
    return false;
  }

  return await bcrypt.compare(password, MASTER_HASH);
}

export function generateTokens(iss: string): [string, string] {
  const TOKEN_SECRET = getTOKEN_SECRET();

  const REFRESH_SECRET = getREFRESH_SECRET();

  const jti = randomUUID();

  const accessToken = jwt.sign({ iss, jti }, TOKEN_SECRET, {
    expiresIn: "5m",
  });

  const refreshToken = jwt.sign({ iss, jti }, REFRESH_SECRET, {
    expiresIn: "7d",
  });

  return [accessToken, refreshToken];
}

export function verifyRefreshToken(
  token: string,
  ip: string
): [boolean, JwtPayload] {
  const REFRESH_SECRET = getREFRESH_SECRET();

  try {
    const decoded = jwt.verify(token, REFRESH_SECRET);
    if (!decoded) {
      return [false, {}];
    }
    if (typeof decoded !== "object") {
      return [false, {}];
    }
    if (!decoded.iss) {
      return [false, {}];
    }
    return [decoded.iss === ip, decoded];
  } catch (e) {
    clack.log.warn(yellow`Failed token refresh attempt from ${ip}`);
    return [false, {}];
  }
}

export function verifyToken(token: string, ip: string): [boolean, JwtPayload] {
  const SECRET = getTOKEN_SECRET();

  try {
    const decoded = jwt.verify(token, SECRET);
    if (!decoded) {
      return [false, {}];
    }
    if (typeof decoded !== "object") {
      return [false, {}];
    }
    if (!decoded.iss) {
      return [false, {}];
    }
    return [decoded.iss === ip, decoded];
  } catch (e) {
    clack.log.warn(yellow`Failed token auth attempt from ${ip} - Error: ${e}`);
    return [false, {}];
  }
}

export async function authMiddleware(
  req: Request,
  res: Response,
  next: NextFunction
) {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      res.status(401).json({ error: "Token invalid" });
      clack.log.warn(
        yellow`Failed token auth attempt from ${req.ip} - No token passed: ${req.headers.authorization}`
      );
      return;
    }

    const ip = req.ip;
    if (!ip) {
      res.status(401).json({ error: "Token invalid" });
      clack.log.warn(
        yellow`Failed token auth attempt from ${req.ip} - No IP found`
      );
      return;
    }

    const [isValid, payload] = verifyToken(token, ip);

    if (!isValid) {
      res.status(401).json({ error: "Token invalid" });
      clack.log.warn(
        yellow`Failed token auth attempt from ${req.ip} - Verify returned false`
      );
      return;
    }

    const blacklisted = await TokenBlacklist.findById(payload.jti);
    if (blacklisted) {
      res.status(401).json({ error: "Token invalid" });
      clack.log.warn(
        yellow`Failed token auth attempt from ${req.ip} - Token blacklisted`
      );
      return;
    }

    next();
  } catch (error) {
    res.status(401).json({ error: "Token invalid" });
    clack.log.warn(
      yellow`Failed token auth attempt from ${req.ip} - Error: ${error}`
    );
    return;
  }
}
