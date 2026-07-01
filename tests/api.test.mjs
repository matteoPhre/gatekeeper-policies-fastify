import { afterEach, describe, expect, it } from "vitest";
import { createApp } from "../src/server.mjs";

describe("fastify playground api", () => {
  const apps = [];

  afterEach(async () => {
    while (apps.length > 0) {
      const app = apps.pop();
      if (app) {
        await app.close();
      }
    }
  });

  it("accepts a strong password", async () => {
    const app = createApp();
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/password/validate",
      payload: { password: "StrongGate#2026" },
    });

    expect(response.statusCode).toBe(200);
    expect(response.json().isValid).toBe(true);
  });

  it("rejects an invalid password", async () => {
    const app = createApp();
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: "/password/validate",
      payload: { password: "weak" },
    });

    expect(response.statusCode).toBe(400);
    expect(response.json().isValid).toBe(false);
  });

  it("blocks expired protected access", async () => {
    const app = createApp();
    apps.push(app);

    const response = await app.inject({
      method: "GET",
      url: "/protected/profile",
      headers: { "x-user-id": "alice" },
    });

    expect(response.statusCode).toBe(403);
    expect(response.json()).toEqual({ code: "PASSWORD_EXPIRED" });
  });
});
