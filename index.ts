/**
 * @jeffaf/rubberband
 *
 * OpenClaw plugin that uses RubberBand static pattern detection to block
 * dangerous exec commands before they execute.
 */

import fs from "node:fs";
import path from "node:path";
import { analyzeCommand } from "./rubberband.js";
import type { RubberBandConfig } from "./rubberband.js";

// Re-export for consumers
export { analyzeCommand, getCategories, getRuleCount } from "./rubberband.js";
export type {
  RubberBandResult,
  RubberBandMatch,
  RubberBandConfig,
  RubberBandCustomRule,
} from "./rubberband.js";

// Tool names that execute shell commands. OpenClaw normalizes "bash" to "exec",
// while some hosted runtimes expose namespaced wrappers like functions.exec_command.
const EXEC_TOOL_NAMES = new Set([
  "exec",
  "exec_command",
  "bash",
  "shell",
  "run",
  "terminal",
  "command",
]);

function resolveLogFile(api: { resolvePath?: (input: string) => string }): string {
  try {
    if (api.resolvePath) {
      return path.join(api.resolvePath("~/.openclaw/logs"), "rubberband.log");
    }
  } catch {
    // fall through to HOME-based path
  }
  return path.join(process.env.HOME || "~", ".openclaw", "logs", "rubberband.log");
}

function writeAuditLog(
  logFile: string,
  entry: {
    disposition: string;
    score: number;
    rules: string[];
    command: string;
    sessionKey?: string;
    agentId?: string;
  },
) {
  try {
    fs.mkdirSync(path.dirname(logFile), { recursive: true });
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
    fs.appendFileSync(logFile, line);
  } catch {
    // Don't break exec pipeline if logging fails
  }
}

function buildApprovalDescription(params: {
  disposition: string;
  score: number;
  rules: string[];
  command: string;
  categories: string;
}): string {
  const categories = params.categories || "unknown";
  const rules = params.rules.length > 0 ? params.rules.join(", ") : "none";
  return [
    `RubberBand classified this exec command as ${params.disposition} with score ${params.score}/100.`,
    `Categories: ${categories}.`,
    `Rules: ${rules}.`,
    `Command: ${params.command.slice(0, 500)}`,
  ].join("\n");
}

function normalizeToolName(toolName: string): string {
  const normalized = toolName.trim().toLowerCase();
  const leaf = normalized.split(".").pop() ?? normalized;
  return leaf === "bash" ? "exec" : leaf;
}

function extractCommand(params: Record<string, unknown>): string | undefined {
  const command = params.command;
  if (typeof command === "string" && command.trim()) {
    return command;
  }

  const cmd = params.cmd;
  if (typeof cmd === "string" && cmd.trim()) {
    return cmd;
  }

  return undefined;
}

/**
 * Plugin definition (OpenClaw plugin module format).
 */
export default {
  id: "rubberband",
  name: "RubberBand",
  description: "Static command pattern detection for exec pipeline security",
  version: "1.4.0",

  register(api: any): void {
    const cfg = api.pluginConfig ?? {};
    const enabled = (cfg.enabled as boolean) ?? true;
    const mode = (cfg.mode as string) ?? "block";

    if (!enabled) {
      api.logger.info("RubberBand plugin disabled by config");
      return;
    }

    const logFile = resolveLogFile(api);
    api.logger.info(`RubberBand plugin active (mode: ${mode}), audit log: ${logFile}`);

    // Build RubberBand config from plugin config
    const rbConfig: Partial<RubberBandConfig> = {
      enabled: true,
      mode: mode === "enforce" ? "block" : (mode as RubberBandConfig["mode"]),
    };

    if (cfg.thresholds && typeof cfg.thresholds === "object") {
      const t = cfg.thresholds as Record<string, number>;
      rbConfig.thresholds = {
        alert: t.alert ?? 40,
        block: t.block ?? 60,
      };
    }

    if (Array.isArray(cfg.allowedDestinations)) {
      rbConfig.allowedDestinations = cfg.allowedDestinations as string[];
    }

    if (Array.isArray(cfg.customRules)) {
      rbConfig.customRules = cfg.customRules as RubberBandConfig["customRules"];
    }

    // System event emitter for block/alert notifications
    const emitEvent = api.runtime?.system?.enqueueSystemEvent;

    // Register the before_tool_call typed hook via api.on()
    // (api.registerHook is for internal HOOK.md events; api.on is for typed plugin hooks)
    api.on(
      "before_tool_call",
      (
        event: { toolName: string; params: Record<string, unknown> },
        ctx: { agentId?: string; sessionKey?: string },
      ) => {
        // Only intercept exec-like tools
        if (!EXEC_TOOL_NAMES.has(normalizeToolName(event.toolName))) return;

        const command = extractCommand(event.params);
        if (!command) return;

        const result = analyzeCommand(command, { config: rbConfig });
        const rules = result.matches.map((m) => m.rule_id);
        const categories = [...new Set(result.matches.map((m) => m.category))].join(", ");

        if (result.disposition === "BLOCK") {
          const rulesStr = rules.join(", ");
          const msg = `🔴 RubberBand BLOCK (score ${result.score}/100): ${rulesStr}\nCommand: ${command.slice(0, 200)}`;
          api.logger.warn(msg);

          writeAuditLog(logFile, {
            disposition: "BLOCK",
            score: result.score,
            rules,
            command: command.slice(0, 500),
            sessionKey: ctx.sessionKey,
            agentId: ctx.agentId,
          });

          // Emit system event so the block is visible in session history
          if (emitEvent && ctx.sessionKey) {
            try {
              emitEvent(msg, { sessionKey: ctx.sessionKey });
            } catch {}
          }

          return {
            block: true,
            blockReason: `RubberBand: blocked (score ${result.score}/100) - ${rulesStr}`,
          };
        }

        if (result.disposition === "ALERT") {
          const rulesStr = rules.join(", ");
          const msg = `⚠️ RubberBand ALERT (score ${result.score}/100): ${rulesStr}\nCommand: ${command.slice(0, 200)}`;
          api.logger.warn(msg);

          writeAuditLog(logFile, {
            disposition: "ALERT",
            score: result.score,
            rules,
            command: command.slice(0, 500),
            sessionKey: ctx.sessionKey,
            agentId: ctx.agentId,
          });

          return {
            requireApproval: {
              title: `RubberBand ALERT: ${categories || rulesStr || "exec command"}`,
              description: buildApprovalDescription({
                disposition: "ALERT",
                score: result.score,
                rules,
                command,
                categories,
              }),
              severity: "warning",
              timeoutMs: 60_000,
              timeoutBehavior: "deny",
              allowedDecisions: ["allow-once", "deny"],
              onResolution: async (decision: string) => {
                writeAuditLog(logFile, {
                  disposition: `ALERT_${decision.toUpperCase()}`,
                  score: result.score,
                  rules,
                  command: command.slice(0, 500),
                  sessionKey: ctx.sessionKey,
                  agentId: ctx.agentId,
                });
              },
            },
          };
        }

        if (result.disposition === "LOG" && result.score > 0) {
          writeAuditLog(logFile, {
            disposition: "LOG",
            score: result.score,
            rules,
            command: command.slice(0, 500),
            sessionKey: ctx.sessionKey,
            agentId: ctx.agentId,
          });
        }

        return;
      },
      { priority: 10 },
    );
  },
};
