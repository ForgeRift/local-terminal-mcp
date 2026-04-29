# Getting Started with local-terminal-mcp

> **You're in the right place if:** You've been using Claude for a few weeks, you keep copying and pasting commands back and forth, and you're tired of it. This plugin lets Claude work directly on your Windows machine — reading files, running commands, managing projects — without you acting as the middleman.

---

## What is this, exactly?

local-terminal-mcp is a Claude Desktop extension that gives Claude audited, security-hardened access to your Windows shell. Once installed, Claude can see your files, run commands, and help you build and manage projects directly — instead of just telling you what to type.

Think of it like hiring an assistant who can actually sit at your computer, rather than one who has to shout instructions through a window.

**What Claude can do with this installed:**
- Browse your files and folders
- Read code, configs, and logs
- Run `npm`, `git`, and approved shell commands
- Search for files or text across your project
- Help you debug by actually looking at what's there

**What Claude cannot do (by design):**
- Delete files
- Install software without your knowledge
- Access your passwords, SSH keys, or cloud credentials
- Make arbitrary outbound network calls (curl, wget, ssh, scp are all permanently RED-blocked)
- Run anything destructive without your explicit confirmation

See [COMMANDS.md](COMMANDS.md) for the full breakdown.

---

## What you'll need before you start

- **Windows 10 or Windows 11** — this plugin is Windows-only
- **Claude Desktop** — the desktop app from [claude.ai/download](https://claude.ai/download)
- **A ForgeRift subscription** — you'll get a license key by email after subscribing at [forgerift.io](https://forgerift.io)
- **An Anthropic API key** *(optional)* — enables AI-assisted safety classification on every `run_command` invocation (not only AMBER-tier commands); a high-risk result may independently block execution. Each call consumes tokens billed to your Anthropic account. Get one at [console.anthropic.com](https://console.anthropic.com) → API Keys → Create new key.

---

## Step-by-step setup

### Step 1 — Install the extension

In Claude Desktop, open **Settings → Extensions** and click **Install Extension**. Select the `local-terminal.mcpb` file you received after subscribing.

Claude Desktop will install the extension automatically. No git clone, no terminal, no config files.

---

### Step 2 — Enter your license key

After installation, Claude Desktop will prompt you for your ForgeRift license key. Paste the key from your welcome email and click **Save**.

If you also have an Anthropic API key, enter it in the **Anthropic API Key** field. This is optional — the plugin works without it, but AI-assisted safety classification won't run for any `run_command` invocation.

**Cost note:** When an Anthropic API key is configured, every shell command Claude runs through this plugin sends a small classification request to Anthropic's API, consuming tokens billed to your Anthropic account at standard API rates. Active developers typically see a few dollars per month; heavier workloads may cost more. The plugin is fully functional without this key — only the AI-assisted safety layer is skipped.

These are two different keys from two different companies. Your **ForgeRift license key** arrives in your welcome email and begins with a ForgeRift-specific prefix. Your **Anthropic API key** comes from [console.anthropic.com](https://console.anthropic.com) and starts with `sk-ant-`. Do not paste one into the other field.

---

### Step 3 — Verify it's working

Open Claude Desktop and start a new conversation. Type:

> "Can you list the files in my Documents folder?"

If Claude responds with an actual file listing, you're connected. If it says it can't access your files, check the [troubleshooting guide](TROUBLESHOOTING.md).

---

## Your first 5 minutes — things to try

Once connected, here are good first things to ask Claude:

**Explore your machine:**
> "What's in my Downloads folder? Are there any large files I should know about?"

**Work with a project:**
> "I have a project at C:\Users\YourName\Projects\my-app — can you look at the folder structure and tell me what kind of project it is?"

**Get help with code:**
> "Read the file at C:\Users\YourName\Projects\my-app\src\index.js and explain what it does."

**Run a safe command:**
> "Check the git status of my project at C:\Users\YourName\Projects\my-app"

**Search for something:**
> "Search all .js files in my project for any place I'm using fetch()"

---

## What can Claude actually do now?

Here's a realistic picture of the kinds of workflows this unlocks:

**For developers:**
- "Find every TODO comment across my project and summarize them"
- "Look at my git log and write a summary of what changed this week"
- "Check my npm audit output and tell me which vulnerabilities I need to address"
- "Search my codebase for any hardcoded strings that look like API keys or tokens"

**For non-developers using AI to build things:**
- "I'm trying to learn — look at this file and explain what each part does, then help me add a new feature"
- "Something broke. Look at the error logs and tell me what's wrong in plain English"
- "Set up a new Node project in my Projects folder and walk me through what you're doing"

**For anyone managing files:**
- "Go through my Downloads folder and tell me what's safe to delete"
- "Find all .pdf files on my desktop and tell me what they are based on their names"
- "Is there a .env file in any of my project folders? Tell me which projects have one"

---

## How to ask Claude for help when you're stuck

Claude can help you troubleshoot its own setup. If something isn't working, try:

> "I just installed local-terminal-mcp and it's not connecting. The error I'm seeing is [paste error here]. What should I check?"

> "I'm getting a RED block when I try to run [command]. Is there a way to do what I'm trying to do that won't be blocked?"

> "Walk me through what local-terminal-mcp is actually doing when I ask you to run a command — I want to understand the security model."

Claude knows the plugin's architecture and can guide you through most issues. The [TROUBLESHOOTING.md](TROUBLESHOOTING.md) file also covers the most common first-run problems.

---

## Something went wrong?

See [TROUBLESHOOTING.md](TROUBLESHOOTING.md) for common issues, or email support@forgerift.io.

---

## Tips & Tricks

### Describe outcomes, not commands
You don't need to tell Claude which tool to use or what command to run. Just describe what you want. *"Why is my build failing?"* works better than *"run npm run build and show me the output."* Claude will read the relevant files, run what it needs to, and come back with a diagnosis.

### Let Claude chain its own steps
Once the plugin is connected, Claude can read a file, find an error, search for where that error originates in the codebase, and suggest a fix — all in one go. You don't need to approve each step. Claude stops and asks only when it hits a blocked command or needs a decision only you can make.

### For large log files and error outputs
Don't paste logs into the chat. Just say *"check the error log in [folder]."* Claude will read it directly — including the full output, not just what fits in a paste. For stack traces that are hundreds of lines long, this makes a real difference.

### Use a Claude Project for persistent context
Add `CLAUDE_CONTEXT.md` (in this repo) to a Claude Project. Every conversation in that project starts with Claude already knowing the full plugin — all tools, the security model, common Windows gotchas. No re-explaining needed across sessions.

### Claude in Chrome — extend Claude to your browser
**Claude in Chrome** is a separate browser extension from Anthropic (beta) that gives Claude access to the web page you're viewing. Used alongside local-terminal-mcp, it unlocks a powerful combination: Claude can read a page (GitHub PR, error dashboard, documentation site) and then act on your machine in the same conversation.

A few examples of what that looks like in practice:
- *"I'm looking at this GitHub PR — what changed?"* Claude reads the PR URL from your browser, gets the branch name, checks `git diff` and `git log` on your local clone, and summarizes what changed. (Note: `git fetch` and `npm test` are not available through the plugin — run those yourself in a terminal.)
- *"This error is showing in my browser console — find where it's coming from in my code."* Claude reads the browser error, searches your local project for the source.
- *"Walk me through what this dependency does"* while you have its npm page open — Claude reads the page and cross-references it against your `package.json`.

Claude in Chrome is available as a beta from [claude.ai](https://claude.ai). Install it, connect it, and it will appear as a tool in the same conversation where local-terminal-mcp is active.

---

## Step 4: Prime Claude with plugin context (recommended)

Claude works even better when it already knows how local-terminal-mcp works — which tools are available, what commands are blocked on Windows, and what to check when something goes wrong. This step primes Claude with that knowledge so it can self-diagnose common issues and give you accurate guidance.

**Pick one option:**

### Option A: Claude Project (best for ongoing use)
1. In Claude, go to **Projects** and open or create a project for your local machine work
2. Add **[CLAUDE_CONTEXT.md](CLAUDE_CONTEXT.md)** as a project file
3. Every conversation in that project automatically has full plugin context

### Option B: Add to Claude Memory
Start a new Claude conversation and paste the contents of [CLAUDE_CONTEXT.md](CLAUDE_CONTEXT.md) into the chat. Claude will read it and use it as context for that session.

---

*Built by [ForgeRift LLC](https://forgerift.io) — [support@forgerift.io](mailto:support@forgerift.io)*
