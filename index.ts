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

type PluginApi = {
  id: string;
  name: string;
  pluginConfig?: Record<string, unknown>;
  logger: {
    info: (msg: string) => void;
    warn: (msg: string) => void;
    error: (msg: string) => void;
  };
  on: (
    hookName: string,
    handler: (event: any, ctx: any) => any,
    opts?: { priority?: number },
  ) => void;
};

/**
 * Plugin entry point.
 */
export default function register(api: PluginApi): void {
  const cfg = api.pluginConfig ?? {};
  const enabled = (cfg.enabled as boolean) ?? true;
  const mode = (cfg.mode as string) ?? "shadow";

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

  // Register the before_tool_call hook with high priority (runs early)
  api.on(
    "before_tool_call",
    (event: { toolName: string; params: Record<string, unknown> }, ctx: { agentId?: string; sessionKey?: string }) => {
      // Only intercept exec-like tools
      if (!EXEC_TOOL_NAMES.has(event.toolName)) return;

      const command = event.params.command;
      if (typeof command !== "string" || !command) return;

      const result = analyzeCommand(command, { config: rbConfig });

      if (result.disposition === "BLOCK") {
        const rules = result.matches.map((m) => m.rule_id).join(", ");
        api.logger.warn(
          `RubberBand BLOCK (score=${result.score}): [${rules}] command="${command.slice(0, 120)}"`,
        );
        return {
          block: true,
          blockReason: `RubberBand: blocked (score ${result.score}/100) — ${rules}`,
        };
      }

      if (result.disposition === "ALERT") {
        const rules = result.matches.map((m) => m.rule_id).join(", ");
        api.logger.warn(
          `RubberBand ALERT (score=${result.score}): [${rules}] command="${command.slice(0, 120)}"`,
        );
      }

      if (result.disposition === "LOG" && result.score > 0) {
        const rules = result.matches.map((m) => m.rule_id).join(", ");
        api.logger.info(
          `RubberBand LOG (score=${result.score}): [${rules}] command="${command.slice(0, 120)}"`,
        );
      }

      // Allow the command
      return;
    },
    { priority: 10 }, // High priority — run before other hooks
  );
}
