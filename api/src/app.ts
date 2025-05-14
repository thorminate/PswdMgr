import { config } from "@dotenvx/dotenvx";
import mongoose from "mongoose";
import express from "express";
import * as clack from "@clack/prompts";
import colors, { AnsiColors } from "ansis";
import {
  authMiddleware,
  generateTokens,
  verifyPassword,
  verifyRefreshToken,
} from "./security/auth.js";
import { decrypt, deriveKey, encrypt } from "./security/crypto.js";
import VaultEntry from "./models/VaultEntry.js";
import https from "node:https";
import bcrypt from "bcrypt";
import { readFileSync, writeFileSync } from "node:fs";
import { appendFile } from "node:fs/promises";
import rateLimit from "express-rate-limit";
import { execa } from "execa";
import jwt, { JwtPayload } from "jsonwebtoken";
import TokenBlacklist from "./models/TokenBlacklist.js";
import { randomBytes, randomUUID } from "node:crypto";

function encasedText(
  str: string,
  bgColor: colors.AnsiColors,
  textColor: colors.AnsiColors
) {
  const bgClrAsBgClr: colors.Ansis =
    colors[("bg" + bgColor[0]!.toUpperCase() + bgColor.slice(1)) as AnsiColors];

  const bgClrAsClr = colors[bgColor];

  const txtClrAsClr = colors[textColor];

  return bgClrAsClr`` + txtClrAsClr.dim(bgClrAsBgClr(str)) + bgClrAsClr``;
}

clack.intro(encasedText("PswdMgr", "blueBright", "blue"));

config({
  quiet: true,
  ignore: ["MISSING_ENV_FILE"],
});

const app = express();
app.use(express.json());

let shouldEncryptEnv = false;

if (!process.env.MASTER_HASH) {
  clack.log.info(colors.black`No master password found.`);
  const password = await clack.password({
    message: "Enter new master password",
    validate(value) {
      if (!value) {
        return "Password is required";
      } else if (value.length < 8) {
        return "Password must be at least 8 characters long";
      }
      return;
    },
  });

  if (clack.isCancel(password)) {
    clack.outro(colors.red`User cancelled setup.`);
    process.exit(1);
  }

  const saltRounds = 13;
  const hash = await bcrypt.hash(password.toString().trim(), saltRounds);

  const trimmedHash = hash.substring(7);

  process.env.MASTER_HASH = trimmedHash;

  await appendFile("./.env", `\nMASTER_HASH="${trimmedHash}"`);

  shouldEncryptEnv = true;
}

if (!process.env.MONGODB_URI) {
  clack.log.info(colors.black`MongoDB URI not found in .env file.`);

  async function prompt() {
    const uri = await clack.password({
      message: "Enter MongoDB URI",
      validate(value) {
        if (!value) {
          return "URI is required";
        }
        return;
      },
    });

    if (clack.isCancel(uri)) {
      clack.outro(colors.red`User cancelled setup.`);
      process.exit(1);
    }

    return uri.toString().trim();
  }

  async function connect(uri: string) {
    try {
      await mongoose.connect(uri);
    } catch (e) {
      clack.log.error(
        colors.red`Invalid MongoDB URI. Could not connect to MongoDB. Try again.`
      );
      uri = await prompt();
      await connect(uri);
    }
  }

  const a = await prompt();

  connect(a);

  process.env.MONGODB_URI = a;

  await appendFile("./.env", `\nMONGODB_URI="${a}"`);

  shouldEncryptEnv = true;
} else {
  await mongoose.connect(process.env.MONGODB_URI);
  clack.log.step(colors.magenta`Connected to MongoDB`);
}

if (!process.env.JWT_SECRET) {
  clack.log.warn(colors.gray`No JWT secret found. Generating a new one.`);
  const newSecret = randomUUID();
  process.env.JWT_SECRET = newSecret;
  await appendFile("./.env", `\nJWT_SECRET="${newSecret}"`);

  shouldEncryptEnv = true;
}

if (!process.env.MASTER_SALT) {
  clack.log.warn(colors.gray`No master salt found. Generating a new one.`);
  const newSalt = randomBytes(16).toString("base64");
  process.env.MASTER_SALT = newSalt;
  await appendFile("./.env", `\nMASTER_SALT="${newSalt}"`);

  shouldEncryptEnv = true;
}

if (shouldEncryptEnv) {
  const s = clack.spinner();
  s.start(colors.black`Encrypting .env file`);

  await execa`npx @dotenvx/dotenvx encrypt ${import.meta.url}/../.env`;

  s.stop(colors.black`Encrypted .env file successfully`);
}

let masterKey: Buffer<ArrayBufferLike>;

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,
  message: { error: "Too many login attempts, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.post("/login", authLimiter, async ({ body: { password }, ip }, res) => {
  const isValid = await verifyPassword(password);
  if (!isValid) {
    clack.log.error(colors.red`Login failed for ${ip}`);
    res.status(401).send({ error: "Login failed" });
    return;
  }
  masterKey = await deriveKey(
    password,
    Buffer.from(process.env.MASTER_SALT!, "base64")
  );

  if (!ip) {
    clack.log.error(colors.yellow`IP address could not be determined`);
    res.status(400).send({
      error: "Your IP address could not be determined",
      hint: "Ensure the request includes proper headers or is not proxied incorrectly.",
    });
    return;
  }

  const [accessToken, refreshToken] = generateTokens(ip);

  clack.log.info(
    colors.blueBright`${ip} authenticated, access token: ${accessToken.substring(
      accessToken.length - 8
    )}`
  );
  res.status(200).json({ token: accessToken, refreshToken });
});

const generalLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100,
  message: { error: "Too many requests, please try again later." },
  standardHeaders: true,
  legacyHeaders: false,
});

app.use(generalLimiter);

app.get("/health", (req, res) => {
  res.status(200).json({ message: "OK" });
});

app.use(authMiddleware);

app.post("/logout", async (req, res) => {
  const token = req.headers.authorization?.split(" ")[1];

  if (!token) {
    res.status(401).send({ error: "Token invalid" });
    clack.log.warn(
      colors.yellow`Failed token auth attempt from ${req.ip} - No token passed: ${req.headers.authorization}`
    );
    return;
  }

  try {
    const { jti, exp } = jwt.verify(
      token,
      process.env.JWT_SECRET || "secret"
    ) as JwtPayload;

    if (!jti || !exp) {
      res.status(401).send({ error: "Token invalid" });
      clack.log.warn(
        colors.yellow`Failed token auth attempt from ${req.ip} - No jti or exp found in token`
      );
      return;
    }

    const expiresAt = new Date(exp * 1000);

    await TokenBlacklist.create({
      _id: jti,
      expiresAt,
    });

    res.status(200).send({ message: "Logged out successfully" });
  } catch (e) {
    res.status(401).send({ error: "Token invalid" });
    clack.log.warn(
      colors.yellow`Failed token auth attempt from ${req.ip} - error: ${e}`
    );
  }
});

app.post("/refresh", async ({ body: { refreshToken }, ip }, res) => {
  if (!refreshToken) {
    clack.log.error(colors.red`Refresh token is missing for ${ip}`);
    res.status(401).send({ error: "Refresh token is missing" });
    return;
  }

  if (!ip) {
    clack.log.error(colors.yellow`IP address could not be determined`);
    res.status(400).send({
      error: "Your IP address could not be determined",
      hint: "Ensure the request includes proper headers or is not proxied incorrectly.",
    });
    return;
  }

  const [isValid, payload] = verifyRefreshToken(refreshToken, ip);
  if (!isValid) {
    clack.log.error(colors.red`Refresh token is invalid for ${ip}`);
    res.status(401).send({ error: "Refresh token is invalid" });
    return;
  }

  await TokenBlacklist.findByIdAndUpdate(
    payload.jti,
    {
      _id: payload.jti,
      expiresAt: new Date(Date.now() + 15 * 60 * 1000),
    },
    { upsert: true, new: true, setDefaultsOnInsert: true }
  );

  const [accessToken, newRefreshToken] = generateTokens(ip);

  clack.log.info(
    colors.blueBright`${ip} refreshed token, access token: ${accessToken.substring(
      accessToken.length - 8
    )}`
  );
  res.status(200).json({ token: accessToken, refreshToken: newRefreshToken });
});

app.post(
  "/change-password",
  async ({ body: { password, oldPassword } }, res) => {
    const isValid = await verifyPassword(oldPassword);
    if (!isValid) {
      res.status(401).send({ error: "Old password is incorrect" });
      return;
    }

    if (!password) {
      res.status(400).send({ error: "New password is required" });
      return;
    }
    password = password.toString().trim();

    const newMasterKey = await deriveKey(
      password,
      Buffer.from(process.env.MASTER_SALT!, "base64")
    );

    // Fetch all entries
    const entries = await VaultEntry.find({});
    for (const entry of entries) {
      if (!entry.encrypted) {
        clack.log.error(
          colors.red`Entry ${entry._id} is malformed, cannot recover data`
        );
        continue;
      }
      // Decrypt the entry with the old password
      const decrypted = await decrypt(masterKey, entry.encrypted);

      // Encrypt the entry with the new password
      const encrypted = await encrypt(newMasterKey, decrypted);

      await VaultEntry.findByIdAndUpdate(entry._id, {
        encrypted,
      });
    }

    const newMasterSalt = randomBytes(16).toString("base64");
    process.env.MASTER_SALT = newMasterSalt;

    masterKey = newMasterKey;

    const saltRounds = 13;
    const hash = await bcrypt.hash(password, saltRounds);

    const trimmedHash = hash.substring(7);
    process.env.MASTER_HASH = trimmedHash;

    const envFile = readFileSync("./.env", "utf8");

    let updates = 0;

    const updatedEnvFile = envFile
      .split("\n")
      .map((line) => {
        if (line.includes("MASTER_HASH=")) {
          updates++;
          return `MASTER_HASH="${trimmedHash}"`;
        } else if (line.includes("MASTER_SALT=")) {
          updates++;
          return `MASTER_SALT="${newMasterSalt}"`;
        } else {
          return line;
        }
      })
      .join("\n");

    writeFileSync("./.env", updatedEnvFile, "utf8");

    clack.log.warn(colors.yellow`Changed master password to ${password}`);

    const s = clack.spinner();
    s.start(colors.black`Encrypting .env file`);

    await execa`npx @dotenvx/dotenvx encrypt ${import.meta.url}/../.env`;

    s.stop(colors.green`Encrypted .env file`);

    res.status(200).json({ message: "Password changed", password });
  }
);

app.post(
  "/entries",
  async ({ body: { id, secret }, headers: { authorization: token } }, res) => {
    if (!id) {
      res.status(400).send({ error: "Id is required" });
      return;
    }
    const encrypted = await encrypt(masterKey, secret);

    const entry = await VaultEntry.findByIdAndUpdate(
      id,
      {
        encrypted,
      },
      { upsert: true, new: true, setDefaultsOnInsert: true }
    );

    clack.log.info(
      colors.green`Created or updated entry ${id} with token: ${token!.substring(
        token!.length - 8
      )}`
    );
    res.status(201).json({
      id: entry._id,
      encrypted: entry.encrypted,
    });
  }
);

app.get("/entries", async (req, res) => {
  const entries = await VaultEntry.find({});

  clack.log.info(
    colors.green`Fetched ${
      entries.length
    } entries with token: ${req.headers.authorization?.substring(
      req.headers.authorization.length - 8
    )}`
  );
  res.status(200).json(entries.map(({ _id }) => _id));
});

app.get("/entries/:id", async (req, res) => {
  const entry = await VaultEntry.findById(req.params.id);

  if (!entry) {
    res.status(404).json({ error: "Entry not found" });
    return;
  } else if (!entry.encrypted) {
    res.status(500).json({ error: "Entry malformed" });
    return;
  }

  const decryptedData = await decrypt(masterKey, entry.encrypted);

  clack.log.info(
    colors.green`Fetched entry ${
      req.params.id
    } with token: ${req.headers.authorization?.substring(
      req.headers.authorization.length - 8
    )}`
  );
  res.status(200).json({ secret: decryptedData, id: entry._id });
});

app.delete("/entries/:id", async (req, res) => {
  const doc = await VaultEntry.findByIdAndDelete(req.params.id);

  if (!doc) {
    res.status(404);
    return;
  }

  clack.log.warn(colors.yellow`Deleted entry ${req.params.id}`);
  res.status(200).json({
    id: doc._id,
    encrypted: doc.encrypted,
  });
});

let server = https
  .createServer(
    {
      key: readFileSync("./src/security/cert/key.pem").toString(),
      cert: readFileSync("./src/security/cert/cert.pem").toString(),
    },
    app
  )
  .listen(443, () => {
    clack.log.success(
      colors.greenBright`Listening on https://localhost:443 🚀`
    );
  })
  .on("error", (e) => {
    if (e.message.includes("EADDRINUSE")) {
      clack.log.error(
        colors.red`HTTPS port 443 is already in use. Trying port 2053...`
      );
      server = https
        .createServer(
          {
            key: readFileSync("./src/security/cert/key.pem"),
            cert: readFileSync("./src/security/cert/cert.pem"),
          },
          app
        )
        .listen(2053, () => {
          clack.log.success(
            colors.greenBright`Listening on https://localhost:2053 🚀`
          );
        })
        .on("error", (e) => {
          if (e.message.includes("EADDRINUSE")) {
            clack.log.error(
              colors.red`HTTPS port 2053 is already in use. Trying port 2083...`
            );
            server = https
              .createServer(
                {
                  key: readFileSync("./src/security/cert/key.pem"),
                  cert: readFileSync("./src/cert/cert.pem"),
                },
                app
              )
              .listen(2083, () => {
                clack.log.success(
                  colors.greenBright`Listening on https://localhost:2083 🚀`
                );
              })
              .on("error", (e) => {
                clack.log.error(
                  colors.red`HTTPS port 2083 is already in use. Trying port 2087...`
                );
                server = https
                  .createServer(
                    {
                      key: readFileSync("./src/security/cert/key.pem"),
                      cert: readFileSync("./src/security/cert/cert.pem"),
                    },
                    app
                  )
                  .listen(2087, () => {
                    clack.log.success(
                      colors.greenBright`Listening on https://localhost:2087 🚀`
                    );
                  })
                  .on("error", (e) => {
                    clack.log.error(
                      colors.red`HTTPS port 2087 is already in use. Trying port 2096...`
                    );
                    server = https
                      .createServer(
                        {
                          key: readFileSync("./src/security/cert/key.pem"),
                          cert: readFileSync("./src/security/cert/cert.pem"),
                        },
                        app
                      )
                      .listen(2096, () => {
                        clack.log.success(
                          colors.greenBright`Listening on https://localhost:2096 🚀`
                        );
                      })
                      .on("error", (e) => {
                        clack.log.error(
                          colors.red`HTTPS port 2096 is already in use. Trying port 8443...`
                        );
                        server = https
                          .createServer(
                            {
                              key: readFileSync("./src/security/cert/key.pem"),
                              cert: readFileSync(
                                "./src/security/cert/cert.pem"
                              ),
                            },
                            app
                          )
                          .listen(8443, () => {
                            clack.log.success(
                              colors.greenBright`Listening on https://localhost:8443 🚀`
                            );
                          })
                          .on("error", (e) => {
                            clack.log.error(
                              colors.red`HTTPS port 8443 is already in use. All ports are in use. Exiting... (what are you running on this machine?!)`
                            );
                            process.exit(1);
                          });
                      });
                  });
              });
          }
        });
    }
  });

process.once("SIGINT", async () => {
  await mongoose.disconnect();
  clack.outro(encasedText("Bye!", "redBright", "red"));
  server.close();
});
