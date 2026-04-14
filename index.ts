/**
 * @jeffaf/openclaw-rubberband
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
export type { RubberBandResult, RubberBandMatch, RubberBandConfig } from "./rubberband.js";

// Tool names that execute shell commands
const EXEC_TOOL_NAMES = new Set(["exec", "shell", "run", "terminal", "command"]);

// Audit log path
const LOG_DIR = path.join(process.env.HOME || "~", ".openclaw", "logs");
const LOG_FILE = path.join(LOG_DIR, "rubberband.log");

function writeAuditLog(entry: {
  disposition: string;
  score: number;
  rules: string[];
  command: string;
  sessionKey?: string;
  agentId?: string;
}) {
  try {
    fs.mkdirSync(LOG_DIR, { recursive: true });
    const line = JSON.stringify({ ts: new Date().toISOString(), ...entry }) + "\n";
    fs.appendFileSync(LOG_FILE, line);
  } catch {
    // Don't break exec pipeline if logging fails
  }
}

/**
 * Plugin definition (OpenClaw plugin module format).
 */
export default {
  id: "rubberband",
  name: "RubberBand",
  description: "Static command pattern detection for exec pipeline security",
  version: "1.2.0",

  register(api: any): void {
    const cfg = api.pluginConfig ?? {};
    const enabled = (cfg.enabled as boolean) ?? true;
    const mode = (cfg.mode as string) ?? "block";

    if (!enabled) {
      api.logger.info("RubberBand plugin disabled by config");
      return;
    }

    api.logger.info(`RubberBand plugin active (mode: ${mode}), audit log: ${LOG_FILE}`);

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
        if (!EXEC_TOOL_NAMES.has(event.toolName)) return;

        const command = event.params.command;
        if (typeof command !== "string" || !command) return;

        const result = analyzeCommand(command, { config: rbConfig });
        const rules = result.matches.map((m) => m.rule_id);
        const categories = [...new Set(result.matches.map((m) => m.category))].join(", ");

        if (result.disposition === "BLOCK") {
          const rulesStr = rules.join(", ");
          const msg = `🔴 RubberBand BLOCK (score ${result.score}/100): ${rulesStr}\nCommand: ${command.slice(0, 200)}`;
          api.logger.warn(msg);

          writeAuditLog({
            disposition: "BLOCK",
            score: result.score,
            rules,
            command: command.slice(0, 500),
            sessionKey: ctx.sessionKey,
            agentId: ctx.agentId,
          });

          // Emit system event so the block is visible in session history
          if (emitEvent && ctx.sessionKey) {
            try { emitEvent(msg, { sessionKey: ctx.sessionKey }); } catch {}
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

          writeAuditLog({
            disposition: "ALERT",
            score: result.score,
            rules,
            command: command.slice(0, 500),
            sessionKey: ctx.sessionKey,
            agentId: ctx.agentId,
          });

          return {
            requireApproval: {
              title: "⚠️ RubberBand Security Alert",
              description: `Suspicious command detected (score ${result.score}/100): ${rulesStr}\n\nCommand: ${command.slice(0, 200)}\n\nCategories: ${categories}`,
              severity: result.score >= 50 ? "warning" : "info",
              timeoutMs: 120000,
              timeoutBehavior: "deny",
            },
          };
        }

        if (result.disposition === "LOG" && result.score > 0) {
          writeAuditLog({
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
