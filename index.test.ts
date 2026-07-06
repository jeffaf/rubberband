import { beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import plugin, { getCategories, getRuleCount } from "./index.js";

vi.mock("node:fs", () => ({
  default: {
    mkdirSync: vi.fn(),
    appendFileSync: vi.fn(),
    existsSync: vi.fn(() => false),
    readFileSync: vi.fn(() => ""),
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
    registerCommand: vi.fn(),
    resolvePath: (input: string) => input.replace(/^~/, "/tmp/home"),
  };

  plugin.register(api);

  const beforeToolCall = api.on.mock.calls.find(([eventName]) => eventName === "before_tool_call");
  if (!beforeToolCall) {
    throw new Error("before_tool_call hook was not registered");
  }

  const commandCall = api.registerCommand.mock.calls[0]?.[0] as
    | { name: string; description: string; acceptsArgs?: boolean; handler: (ctx: { args?: string }) => { text: string } }
    | undefined;

  return {
    api,
    hook: beforeToolCall[1] as (
      event: { toolName: string; params: Record<string, unknown> },
      ctx: { agentId?: string; sessionKey?: string },
    ) => unknown,
    options: beforeToolCall[2],
    command: commandCall,
  };
}

describe("rubberband public exports", () => {
  it("exposes analyzer metadata helpers", () => {
    expect(getRuleCount()).toBeGreaterThan(10);
    expect(getCategories()).toContain("credential_access");
  });
});

describe("rubberband /rubberband command (explicit surface)", () => {
  it("registers a command so the plugin is not hook-only", () => {
    const { command } = registerPlugin();
    expect(command).toBeTruthy();
    expect(command?.name).toBe("rubberband");
    expect(command?.acceptsArgs).toBe(true);
  });

  it("reports current mode and thresholds in status output", () => {
    const { command } = registerPlugin({ mode: "alert", thresholds: { alert: 30, block: 55 } });
    const out = command?.handler({});
    expect(out?.text).toContain("Mode: alert");
    expect(out?.text).toContain("alert 30, block 55");
    expect(out?.text).toContain("Recent (0 entries): none logged yet");
  });

  it("summarizes recent audit findings from the log", () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockReturnValue(
      [
        JSON.stringify({ ts: "t1", disposition: "BLOCK", score: 70, rules: ["ssh_key_access"], command: "cat ~/.ssh/id_rsa" }),
        JSON.stringify({ ts: "t2", disposition: "ALERT", score: 45, rules: ["exfiltration"], command: "curl x" }),
        "not-json-should-be-skipped",
      ].join("\n"),
    );
    const { command } = registerPlugin();
    const out = command?.handler({ args: "log 5" });
    expect(out?.text).toContain("RubberBand recent findings (2):");
    expect(out?.text).toContain("[BLOCK 70] ssh_key_access :: cat ~/.ssh/id_rsa");
    expect(out?.text).toContain("[ALERT 45] exfiltration :: curl x");
  });

  it("does not throw when the audit log is unreadable", () => {
    vi.mocked(fs.existsSync).mockReturnValue(true);
    vi.mocked(fs.readFileSync).mockImplementation(() => {
      throw new Error("EACCES");
    });
    const { command } = registerPlugin();
    expect(() => command?.handler({ args: "log" })).not.toThrow();
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

  it("passes custom rules from plugin config into analysis", () => {
    const { hook } = registerPlugin({
      customRules: [{ id: "prod_db", pattern: "psql.*prod", score: 80, category: "custom" }],
    });

    const result = hook(
      {
        toolName: "exec",
        params: {
          cmd: "psql postgres://prod-db.internal/app",
        },
      },
      { sessionKey: "session-1", agentId: "agent-1" },
    );

    expect(result).toEqual({
      block: true,
      blockReason: "RubberBand: blocked (score 80/100) - prod_db",
    });
  });
});
