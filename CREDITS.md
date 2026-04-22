# CMD Connector — Credits & Acknowledgments

This document lists the open-source dependencies used by the CMD Connector and their respective licenses.

---

## Direct Dependencies

### @modelcontextprotocol/sdk
- **Purpose:** MCP server framework
- **Version:** ^1.10.2
- **License:** MIT
- **Author:** Anthropic
- **Homepage:** https://github.com/anthropics/mcp-sdk

### express
- **Purpose:** HTTP server framework
- **Version:** ^4.18.2
- **License:** MIT
- **Author:** TJ Holowaychuk and Express.js contributors
- **Homepage:** https://expressjs.com

### dotenv
- **Purpose:** Environment variable loading from .env files
- **Version:** ^16.4.5
- **License:** BSD-2-Clause
- **Author:** motdotla
- **Homepage:** https://github.com/motdotla/dotenv

---

## Dev Dependencies

### @types/express
- **Purpose:** TypeScript type definitions for Express
- **Version:** ^4.17.21
- **License:** MIT
- **Author:** DefinitelyTyped Contributors
- **Homepage:** https://github.com/DefinitelyTyped/DefinitelyTyped

### @types/node
- **Purpose:** TypeScript type definitions for Node.js
- **Version:** ^20.11.5
- **License:** MIT
- **Author:** DefinitelyTyped Contributors
- **Homepage:** https://github.com/DefinitelyTyped/DefinitelyTyped

### typescript
- **Purpose:** TypeScript compiler
- **Version:** ^5.3.3
- **License:** Apache 2.0
- **Author:** Microsoft
- **Homepage:** https://www.typescriptlang.org

---

## Transitive Dependencies

The following dependencies are included transitively through the direct dependencies listed above:

- **accepts** — MIT
- **array-flatten** — MIT
- **body-parser** — MIT
- **bytes** — MIT
- **call-bind** — MIT
- **content-disposition** — MIT
- **content-type** — MIT
- **cookie** — MIT
- **cookie-signature** — MIT
- **debug** — MIT
- **depd** — MIT
- **destroy** — MIT
- **ee-first** — MIT
- **encodeurl** — MIT
- **escape-html** — MIT
- **etag** — MIT
- **finalhandler** — MIT
- **forwarded** — MIT
- **fresh** — MIT
- **function-bind** — MIT
- **get-intrinsic** — MIT
- **has** — MIT
- **has-property-descriptors** — MIT
- **has-proto** — MIT
- **has-symbols** — MIT
- **http-errors** — MIT
- **iconv-lite** — Apache 2.0
- **inherits** — ISC
- **ipaddr.js** — MIT
- **media-typer** — MIT
- **merge-descriptors** — MIT
- **methods** — MIT
- **mime** — MIT
- **mime-db** — MIT
- **mime-types** — MIT
- **ms** — MIT
- **negotiator** — MIT
- **object-inspect** — MIT
- **on-finished** — MIT
- **parseurl** — MIT
- **path-to-regexp** — MIT
- **proxy-addr** — MIT
- **qs** — BSD-3-Clause
- **range-parser** — MIT
- **raw-body** — MIT
- **safe-buffer** — MIT
- **safer-buffer** — MIT
- **send** — MIT
- **serve-static** — MIT
- **setprototypeof** — ISC
- **side-channel** — MIT
- **statuses** — MIT
- **toidentifier** — MIT
- **unpipe** — MIT
- **vary** — MIT

---

## License Summary

| License | Count |
|---|---|
| MIT | ~85% of transitive deps |
| Apache 2.0 | 2 (typescript, iconv-lite) |
| BSD-2-Clause | 1 (dotenv) |
| BSD-3-Clause | 1 (qs) |
| ISC | 3 (inherits, setprototypeof, and others) |

---

## How to View Full Dependency Tree

To see the complete dependency tree with versions, run:

```bash
npm list
```

To export a detailed report:

```bash
npm list --depth=0
npm list --all
```

---

## License Compliance

All transitive dependencies are permissively licensed (MIT, Apache 2.0, BSD variants, ISC). No GPL, AGPL, or other copyleft licenses are included.

The CMD Connector is distributed under the MIT License. See LICENSE file in the repository root.

---

## Attribution & Thanks

ForgeRift extends gratitude to:
- **Anthropic** for the Model Context Protocol specification and SDK
- **Express.js contributors** for building a robust HTTP framework
- **The Node.js ecosystem** for providing excellent tooling and libraries
- **DefinitelyTyped contributors** for maintaining TypeScript definitions

---

**ForgeRift LLC 2026**

Last updated: April 15, 2026
