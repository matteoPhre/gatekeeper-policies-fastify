import crypto from "node:crypto";
import { pathToFileURL } from "node:url";
import Fastify from "fastify";
import {
  IdentityPolicyEngine,
  createCodeSendExpiryHook,
} from "@matteophre/gatekeeper-policies";

const PORT = Number(process.env.PORT ?? 3002);

function sha256(input) {
  return crypto.createHash("sha256").update(input, "utf8").digest("hex");
}

function toUtf8String(value) {
  if (typeof value === "string") {
    return value;
  }

  return Buffer.from(value).toString("utf8");
}

const users = new Map([
  [
    "alice",
    {
      passwordCreatedAt: new Date("2024-01-01T00:00:00.000Z"),
      passwordHistory: [sha256("OldPassword#2024"), sha256("OlderPassword#2023")],
    },
  ],
  [
    "bob",
    {
      passwordCreatedAt: new Date(),
      passwordHistory: [sha256("BobPassword#2026")],
    },
  ],
]);

const engine = new IdentityPolicyEngine({
  minLength: 12,
  maxLength: 64,
  requireUppercase: true,
  requireLowercase: true,
  requireNumbers: true,
  requireSymbols: true,
  expiryDays: 30,
  historyLimit: 5,
  denyList: ["password", "qwerty", "admin"],
  preventRepeatedChars: true,
  maxRepeatedChars: 2,
  preventSequentialChars: true,
  maxSequentialChars: 4,
  normalizeTrim: true,
  normalizeUnicode: true,
  unicodeNormalizationForm: "NFKC",
  persistence: {
    async getPasswordHistory(userId) {
      return users.get(userId)?.passwordHistory ?? [];
    },
    async saveNewPassword(userId, newHash) {
      const existing = users.get(userId) ?? {
        passwordCreatedAt: new Date(),
        passwordHistory: [],
      };

      const updatedHistory = [newHash, ...existing.passwordHistory].slice(0, 5);
      users.set(userId, {
        passwordCreatedAt: new Date(),
        passwordHistory: updatedHistory,
      });
    },
  },
});

export function createApp() {
  const app = Fastify({ logger: false });

  const expiryHook = createCodeSendExpiryHook({
    getUserIdAndDateFn: async (req) => {
      const userId = String(req.headers["x-user-id"] ?? "").trim();
      if (!userId) {
        throw new Error("Missing x-user-id header.");
      }

      const user = users.get(userId);
      const headerDate = req.headers["x-password-created-at"];
      const passwordCreatedAt = headerDate
        ? new Date(String(headerDate))
        : user?.passwordCreatedAt ?? new Date(0);

      return { userId, passwordCreatedAt };
    },
    evaluatePasswordExpiryDecision: (passwordCreatedAt) =>
      engine.evaluatePasswordExpiryDecision(passwordCreatedAt),
  });

  app.get("/", async () => ({
    service: "gatekeeper-policies-fastify",
    message: "Use /password/validate, /password/change and /protected/profile",
    users: ["alice", "bob"],
  }));

  app.get("/demo/users", async () => {
    return Array.from(users.entries()).map(([userId, data]) => ({
      userId,
      passwordCreatedAt: data.passwordCreatedAt.toISOString(),
      historyCount: data.passwordHistory.length,
    }));
  });

  app.post("/password/validate", async (req, reply) => {
    const password = String(req.body?.password ?? "");
    const complexity = engine.validateComplexity(password);
    const code = complexity.isValid ? 200 : 400;
    return reply.code(code).send(complexity);
  });

  app.post("/password/change", async (req, reply) => {
    const userId = String(req.body?.userId ?? "").trim();
    const newPassword = String(req.body?.newPassword ?? "");

    if (!userId || !newPassword) {
      return reply.code(400).send({
        code: "BAD_REQUEST",
        message: "userId and newPassword are required.",
      });
    }

    const complexity = engine.validateComplexity(newPassword);
    if (!complexity.isValid) {
      return reply.code(400).send({
        code: "WEAK_PASSWORD",
        details: complexity.errors,
      });
    }

    const canRotate = await engine.validateRotation(
      newPassword,
      userId,
      async (candidate, encrypted) => sha256(toUtf8String(candidate)) === encrypted,
    );

    if (!canRotate) {
      return reply.code(409).send({
        code: "PASSWORD_REUSED",
        message: "Password was already used recently.",
      });
    }

    await engine.getConfig().persistence.saveNewPassword(userId, sha256(newPassword));

    return reply.code(200).send({
      code: "PASSWORD_UPDATED",
      userId,
    });
  });

  app.get(
    "/protected/profile",
    { preHandler: expiryHook },
    async (req) => {
      const userId = String(req.headers["x-user-id"] ?? "unknown");
      return {
        userId,
        profile: {
          role: "demo-user",
          data: "Access granted: password policy check passed.",
        },
      };
    },
  );

  app.setErrorHandler((error, _req, reply) => {
    reply.code(400).send({
      code: "BAD_REQUEST",
      message: error instanceof Error ? error.message : "Unexpected error.",
    });
  });

  return app;
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  createApp().listen({ port: PORT, host: "0.0.0.0" }).then(() => {
    console.log(`Fastify playground running on http://localhost:${PORT}`);
  });
}
