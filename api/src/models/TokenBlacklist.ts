import { model, Schema } from "mongoose";

const TokenBlacklistSchema = new Schema({
  _id: String,
  expiresAt: { type: Date, required: true },
});

TokenBlacklistSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

const TokenBlacklist = model("TokenBlacklist", TokenBlacklistSchema);

export default TokenBlacklist;
