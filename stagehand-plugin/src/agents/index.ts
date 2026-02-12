// PhishGuard Plugin - Agent Wrappers
// Self-contained agent implementations adapted from server agents.
// These operate on external Playwright Pages (from Stagehand).

export { PluginUrlAgent } from "./url-agent.js";
export { PluginDomainAgent } from "./domain-agent.js";
export { PluginContentAgent } from "./content-agent.js";
export { PluginHeuristicAgent } from "./heuristic-agent.js";
export { PluginTesterAgent } from "./tester-agent.js";
