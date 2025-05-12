import { model, Schema } from "mongoose";

const VaultEntrySchema = new Schema(
  {
    _id: String,
    encrypted: String,
  },
  { timestamps: true }
);

export default model("VaultEntry", VaultEntrySchema);
