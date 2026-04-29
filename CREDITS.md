# local-terminal-mcp — Credits & Acknowledgments

This document lists the open-source dependencies used by local-terminal-mcp and their respective licenses.

---

## Direct Dependencies

### @modelcontextprotocol/sdk
- **Purpose:** MCP server framework (stdio transport)
- **Version:** ^1.10.2
- **License:** MIT
- **Author:** Anthropic
- **Homepage:** https://github.com/anthropics/mcp-sdk

### @anthropic-ai/sdk
- **Version:** ^0.38.0
- **Purpose:** Anthropic API client for AI-assisted safety classification (optional, requires user-supplied API key)
- **License:** MIT
- **Author:** Anthropic
- **Homepage:** https://github.com/anthropics/anthropic-sdk-typescript

### dotenv
- **Purpose:** Loads environment variables from `.env` files during development
- **License:** BSD-2-Clause
- **Homepage:** https://github.com/motdotla/dotenv

---

## Dev Dependencies

### @types/node
- **Purpose:** TypeScript type definitions for Node.js
- **License:** MIT
- **Author:** DefinitelyTyped Contributors
- **Homepage:** https://github.com/DefinitelyTyped/DefinitelyTyped

### typescript
- **Purpose:** TypeScript compiler
- **License:** Apache 2.0
- **Author:** Microsoft
- **Homepage:** https://www.typescriptlang.org

---

## License Summary

All included dependencies are permissively licensed (MIT, Apache 2.0, BSD-2-Clause). No GPL, AGPL, or other copyleft licenses are included.

local-terminal-mcp is distributed under the MIT License. See LICENSE file in the repository root.

---

## Attribution & Thanks

ForgeRift extends gratitude to:
- **Anthropic** for the Model Context Protocol specification, SDK, and Claude AI platform
- **The Node.js ecosystem** for excellent tooling and libraries
- **DefinitelyTyped contributors** for maintaining TypeScript definitions

---

> **Note:** This file is manually maintained. For the authoritative dependency list, run `npm list --depth=0` against the installed package.

**ForgeRift LLC 2026**

Last updated: 2026-04-29
