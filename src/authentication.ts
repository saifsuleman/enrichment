import mongo from "mongodb";
import crypto from "crypto";
import db from "./mongodatabase";

export default class AuthenticationHandler {
  tokens: Record<string, string>; // maps { token: username }

  constructor() {
    this.tokens = {};
  }

  generateSalt(rounds: number) {
    return crypto
      .randomBytes(Math.ceil(rounds / 2))
      .toString("hex")
      .slice(0, rounds);
  }

  hash(password: string, salt: string) {
    const h = crypto.createHmac(`sha512`, salt);
    h.update(password);
    return h.digest("hex");
  }

  createToken(): string {
    return crypto.randomBytes(16).toString("hex");
  }

  async validate(username: string, password: string): Promise<boolean> {
    return new Promise<boolean>((resolver) => {
      if (!this.database) return resolver(false);

      this.database
        .collection("logins")
        .findOne({ _id: username }, (err, res) => {
          if (!res || err) return resolver(false);
          return resolver(res.hash == this.hash(password, res.salt));
        });
    });
  }

  get database() {
    return db.db("authentication");
  }

  async register(username: string, password: string): Promise<boolean> {
    return new Promise<boolean>((resolver) => {
      if (!this.database) return resolver(false);

      const salt = this.generateSalt(12);
      const hash = this.hash(password, salt);

      const entry = { _id: username, hash, salt };

      this.database.collection("logins").insertOne(entry as any, (err) => {
        return resolver(err == null);
      });
    });
  }

  async authenticate(
    username: string,
    password: string
  ): Promise<string | undefined> {
    const valid = await this.validate(username, password);
    if (!valid) return undefined;
    const token = this.createToken();
    this.tokens[token] = username;
    return token;
  }
}
