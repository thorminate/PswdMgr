import PswdMgrClient from "pswd-mgr-sdk";
import * as clack from "@clack/prompts";

clack.intro(`PswdMgr CLI`);

let client: PswdMgrClient;

async function promptForConnectionString(): Promise<string> {
  let connectionString = await clack.text({
    message: "Enter API connection string",
    validate(value) {
      if (!value) {
        return "Connection string cannot be empty";
      }
      if (!value.startsWith("https://") && !value.startsWith("http://")) {
        return "Connection string must start with a valid protocol (http or https)";
      }
      return;
    },
  });

  if (clack.isCancel(connectionString)) {
    clack.cancel("User cancelled");
    process.exit(0);
  }

  if (typeof connectionString !== "string") {
    clack.log.error("Invalid connection string");
    connectionString = await promptForConnectionString();
  }

  return connectionString;
}

let connectionString = await promptForConnectionString();

if (!connectionString) {
  console.error("Connection string is required");
}

client = new PswdMgrClient({
  connectionString,
});

if (!client!) {
  console.error("Failed to create PswdMgrClient");
  process.exit(1);
}

await client.testConnection().catch(async (e) => {
  console.error("Failed to connect to PswdMgr API");
});
