import express from "express";
import http from "http";
import AuthenticationHandler from "./authentication";

const PORT = 3001;

export default class EnrichmentServer {
  server: http.Server;
  app: express.Application;
  authhandler: AuthenticationHandler;

  constructor() {
    this.app = express();
    this.server = http.createServer(this.app);
    this.server.listen(PORT, "0.0.0.0", () =>
      console.log(`Listening on port ${PORT}`)
    );

    this.authhandler = new AuthenticationHandler();

    this.app.use(express.urlencoded({ extended: true }));
    this.app.use(express.json());

    this.app.get("/authenticate", (req, res) => this.authenticate(req, res));
    this.app.get(`/checktoken`, (req, res) => this.checkToken(req, res));
    this.app.get(`/register`, (req, res) => this.register(req, res));
  }

  async register(req: express.Request, res: express.Response) {
    const { username, password } = req.query as {
      username: string;
      password: string;
    };

    if (!username || !password) {
      return res
        .status(400)
        .send({ error: "username and password fields required." });
    }

    const success = await this.authhandler.register(username, password);
    return res.status(200).send({ success });
  }

  async authenticate(req: express.Request, res: express.Response) {
    const { username, password } = req.query as {
      username: string;
      password: string;
    };

    if (!username || !password) {
      return res
        .status(400)
        .send({ error: "username and password fields required." });
    }

    const token = await this.authhandler.authenticate(username, password);
    if (!token) {
      return res.status(400).send({ error: "invalid login " });
    }

    return res.status(200).send({ token });
  }

  async checkToken(req: express.Request, res: express.Response) {
    const { token } = req.query as { token: string };

    if (!token) {
      return res.status(400).send({ error: "'token' field required" });
    }

    return res
      .status(200)
      .send({ token, username: this.authhandler.tokens[token] });
  }
}

new EnrichmentServer();
