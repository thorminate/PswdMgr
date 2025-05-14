import axios, { AxiosResponse } from "axios";
import https from "https";

interface Token {
  str: string;
  refreshToken: string;
  expiresAt: number;
}

interface VaultEntry {
  id: string;
  secret: string;
}

interface EncryptedVaultEntry {
  id: string;
  encrypted: string;
}

const httpsAgent = new https.Agent({
  rejectUnauthorized: false,
});

interface PswdMgrClientOptions {
  connectionString: string;
}

export default class PswdMgrClient {
  private connectionString: string;
  private password?: string;
  private token?: Token;

  constructor({ connectionString }: PswdMgrClientOptions) {
    this.connectionString = connectionString;
  }

  async login(password: string): Promise<void> {
    this.password = password;

    const res = await axios
      .post(
        this.connectionString + "/login",
        { password },
        {
          httpsAgent,
          validateStatus: () => true,
        }
      )
      .catch((e) => {
        if (e.code === "ECONNREFUSED") {
          throw new Error(
            "ECONNREFUSED: Could not connect to server (is it running?)"
          );
        } else {
          throw e;
        }
      });

    if (res.status !== 200) {
      throw new Error("Authentication failed", { cause: res.data });
    }

    this.token = {
      str: res.data.token,
      refreshToken: res.data.refreshToken,
      expiresAt: Date.now() + 15 * 60 * 1000,
    };
  }

  async refresh(): Promise<void> {
    if (!this.password) {
      throw new Error("No password set to refresh token");
    }

    const res = await axios.post(
      this.connectionString + "/refresh",
      { refreshToken: this.token?.refreshToken },
      {
        headers: {
          Authorization: `Bearer ${this.token?.str}`,
        },
        httpsAgent,
        validateStatus: () => true,
      }
    );

    if (res.status !== 200) {
      throw new Error("Refresh failed", { cause: res.data });
    }

    this.token = {
      str: res.data.token,
      refreshToken: res.data.refreshToken,
      expiresAt: Date.now() + 5 * 60 * 1000,
    };
  }

  async logout(): Promise<void> {
    await axios.post(
      this.connectionString + "/logout",
      {},
      {
        headers: {
          Authorization: `Bearer ${this.token?.str}`,
        },
        httpsAgent,
        validateStatus: () => true,
      }
    );
  }

  async testConnection(): Promise<void> {
    const res = await axios
      .get(this.connectionString + "/health", {
        httpsAgent,
        validateStatus: () => true,
      })
      .catch((e) => {
        return;
      });

    if (!res) {
      throw new Error("Connection failed");
    }

    if (res.status !== 200) {
      throw new Error("Connection failed");
    }
  }

  private async request(
    method: string,
    path: string,
    data: any = null
  ): Promise<AxiosResponse<any, any>> {
    if (!this.token) {
      throw new Error("Not logged in");
    } else if (this.token.expiresAt < Date.now()) {
      await this.refresh();
    }

    const res = await axios({
      method,
      url: this.connectionString + path,
      headers: {
        Authorization: `Bearer ${this.token?.str}`,
      },
      httpsAgent,
      validateStatus: () => true,
      data,
    });

    if (res.status === 401) {
      throw new Error("Login failed");
    }

    return res;
  }

  async fetchAllEntries(): Promise<string[]> {
    const res = await this.request("get", "/entries");
    return res.data;
  }

  async changePassword(oldPassword: string, password: string): Promise<void> {
    const res = await this.request("post", "/change-password", {
      password,
      oldPassword,
    });

    if (!res.data.password) {
      throw new Error("Failed to change password");
    }

    this.password = res.data.password;
    this.refresh();
  }

  async deleteEntry(id: string): Promise<EncryptedVaultEntry> {
    const res = await this.request(
      "delete",
      "/entries/" + encodeURIComponent(id)
    );
    return res.data;
  }

  async fetchEntry(id: string): Promise<VaultEntry | undefined> {
    const res = await this.request("get", "/entries/" + encodeURIComponent(id));

    if (!res.data.secret) {
      return undefined;
    }

    return res.data;
  }

  async setEntry(id: string, secret: string): Promise<EncryptedVaultEntry> {
    const res = await this.request("post", "/entries", {
      id,
      secret,
    });

    return res.data;
  }
}
