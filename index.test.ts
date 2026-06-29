import { beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import plugin, { getCategories, getRuleCount } from "./index.js";

vi.mock("node:fs", () => ({
  default: {
    mkdirSync: vi.fn(),
    appendFileSync: vi.fn(),
  },
}));

beforeEach(() => {
  vi.clearAllMocks();
});

function registerPlugin(pluginConfig: Record<string, unknown> = {}) {
  const api = {
    pluginConfig,
    logger: {
      info: vi.fn(),
      warn: vi.fn(),
    },
    runtime: {
      system: {
        enqueueSystemEvent: vi.fn(),
      },
    },
    on: vi.fn(),
    resolvePath: (input: string) => input.replace(/^~/, "/tmp/home"),
  };

  plugin.register(api);

  const beforeToolCall = api.on.mock.calls.find(([eventName]) => eventName === "before_tool_call");
  if (!beforeToolCall) {
    throw new Error("before_tool_call hook was not registered");
  }

  return {
    api,
    hook: beforeToolCall[1] as (
      event: { toolName: string; params: Record<string, unknown> },
      ctx: { agentId?: string; sessionKey?: string },
    ) => unknown,
    options: beforeToolCall[2],
  };
}

describe("rubberband public exports", () => {
  it("exposes analyzer metadata helpers", () => {
    expect(getRuleCount()).toBeGreaterThan(10);
    expect(getCategories()).toContain("credential_access");
  });
});

describe("rubberband plugin before_tool_call hook", () => {
  it("requests approval for ALERT disposition", () => {
    const { api, hook, options } = registerPlugin();

    const result = hook(
      {
        toolName: "exec",
        params: {
          command: "curl -X POST -d test=http://localhost http://localhost/api",
        },
      },
      { sessionKey: "session-1", agentId: "agent-1" },
    );

    expect(options).toEqual({ priority: 10 });
    expect(result).toMatchObject({
      requireApproval: {
        title: "RubberBand ALERT: exfiltration",
        severity: "warning",
        timeoutMs: 60_000,
        timeoutBehavior: "deny",
        allowedDecisions: ["allow-once", "deny"],
      },
    });
    expect(api.runtime.system.enqueueSystemEvent).not.toHaveBeenCalled();
    expect(api.logger.warn).toHaveBeenCalledOnce();
    expect(fs.mkdirSync).toHaveBeenCalledOnce();
    expect(fs.appendFileSync).toHaveBeenCalledOnce();
  });

  it("records approval resolution for ALERT disposition", async () => {
    const { api, hook } = registerPlugin({ mode: "alert" });

    const result = hook(
      {
        toolName: "exec",
        params: {
          command: "curl -X POST -d test=http://localhost http://localhost/api",
        },
      },
      { sessionKey: "session-1", agentId: "agent-1" },
    ) as {
      requireApproval?: {
        onResolution?: (decision: string) => Promise<void> | void;
      };
    };

    expect(result?.requireApproval).toBeTruthy();
    expect(api.logger.warn).toHaveBeenCalledOnce();
    expect(fs.appendFileSync).toHaveBeenCalledOnce();
    await result.requireApproval?.onResolution?.("deny");
    expect(fs.appendFileSync).toHaveBeenCalledTimes(2);
  });

  it("keeps hard blocking for BLOCK disposition", () => {
    const { api, hook } = registerPlugin();

    const result = hook(
      {
        toolName: "exec",
        params: {
          command: "cat ~/.ssh/id_rsa",
        },
      },
      { sessionKey: "session-1", agentId: "agent-1" },
    );

    expect(result).toEqual({
      block: true,
      blockReason: "RubberBand: blocked (score 70/100) - ssh_key_access",
    });
    expect(api.runtime.system.enqueueSystemEvent).toHaveBeenCalledOnce();
  });

  it("extracts command text from current OpenClaw cmd-shaped exec params", () => {
    const { api, hook } = registerPlugin();

    const result = hook(
      {
        toolName: "exec",
        params: {
          cmd: "cat ~/.ssh/id_rsa",
        },
      },
      { sessionKey: "session-1", agentId: "agent-1" },
    );

    expect(result).toEqual({
      block: true,
      blockReason: "RubberBand: blocked (score 70/100) - ssh_key_access",
    });
    expect(api.runtime.system.enqueueSystemEvent).toHaveBeenCalledOnce();
  });

  it("recognizes namespaced Codex exec_command wrappers", () => {
    const { api, hook } = registerPlugin();

    const result = hook(
      {
        toolName: "functions.exec_command",
        params: {
          cmd: "cat ~/.ssh/id_rsa",
        },
      },
      { sessionKey: "session-1", agentId: "agent-1" },
    );

    expect(result).toEqual({
      block: true,
      blockReason: "RubberBand: blocked (score 70/100) - ssh_key_access",
    });
    expect(api.runtime.system.enqueueSystemEvent).toHaveBeenCalledOnce();
  });
});
