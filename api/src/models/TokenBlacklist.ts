import { model, Schema } from "mongoose";

const TokenBlacklistSchema = new Schema({
  jti: { type: String, required: true, unique: true },
  expiresAt: { type: Date, required: true },
});

TokenBlacklistSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const TokenBlacklist = model("TokenBlacklist", TokenBlacklistSchema);

export default TokenBlacklist;
