/**
 * @jeffaf/openclaw-rubberband
 *
 * OpenClaw plugin that uses RubberBand static pattern detection to block
 * dangerous exec commands before they execute.
 */

import { analyzeCommand } from "./rubberband.js";
import type { RubberBandConfig } from "./rubberband.js";

// Re-export for consumers
export { analyzeCommand, getCategories, getRuleCount } from "./rubberband.js";
export type { RubberBandResult, RubberBandMatch, RubberBandConfig } from "./rubberband.js";

// Tool names that execute shell commands
const EXEC_TOOL_NAMES = new Set(["exec", "shell", "run", "terminal", "command"]);

/**
 * Plugin definition (OpenClaw plugin module format).
 */
export default {
  id: "rubberband",
  name: "RubberBand",
  description: "Static command pattern detection for exec pipeline security",
  version: "1.0.1",

  register(api: any): void {
    const cfg = api.pluginConfig ?? {};
    const enabled = (cfg.enabled as boolean) ?? true;
    const mode = (cfg.mode as string) ?? "block";

    if (!enabled) {
      api.logger.info("RubberBand plugin disabled by config");
      return;
    }

    api.logger.info(`RubberBand plugin active (mode: ${mode})`);

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

        if (result.disposition === "BLOCK") {
          const rules = result.matches.map((m) => m.rule_id).join(", ");
          const msg = `🔴 RubberBand BLOCK (score ${result.score}/100): ${rules}\nCommand: ${command.slice(0, 200)}`;
          api.logger.warn(msg);

          // Emit system event so the block is visible in session history
          if (emitEvent && ctx.sessionKey) {
            try { emitEvent(msg, { sessionKey: ctx.sessionKey }); } catch {}
          }

          return {
            block: true,
            blockReason: `RubberBand: blocked (score ${result.score}/100) - ${rules}`,
          };
        }

        if (result.disposition === "ALERT") {
          const rules = result.matches.map((m) => m.rule_id).join(", ");
          const msg = `⚠️ RubberBand ALERT (score ${result.score}/100): ${rules}\nCommand: ${command.slice(0, 200)}`;
          api.logger.warn(msg);

          if (emitEvent && ctx.sessionKey) {
            try { emitEvent(msg, { sessionKey: ctx.sessionKey }); } catch {}
          }
        }

        if (result.disposition === "LOG" && result.score > 0) {
          const rules = result.matches.map((m) => m.rule_id).join(", ");
          api.logger.info(
            `LOG (score=${result.score}): [${rules}] command="${command.slice(0, 120)}"`,
          );
        }

        return;
      },
      { priority: 10 },
    );
  },
};
