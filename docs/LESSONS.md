# Lessons

One entry per surprise or real bug: what happened, root cause, fix, and the rule that prevents it.

## 2026-11-19: `mcp` 2.x renamed FastMCP
- **What happened:** `from mcp.server.fastmcp import FastMCP` raised `ModuleNotFoundError` on a fresh install.
- **Root cause:** `mcp` 2.0 renamed `FastMCP` to `MCPServer` (`mcp.server.mcpserver`). Most tutorials still show the 1.x import.
- **Fix:** use `MCPServer`, pin `mcp>=2.3,<3`.
- **Rule:** check the installed SDK version and its API before writing code from memory or tutorials.
