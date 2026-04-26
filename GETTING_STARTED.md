# Getting Started with local-terminal-mcp

> **You're in the right place if:** You've been using Claude for a few weeks, you keep copying and pasting commands back and forth, and you're tired of it. This plugin lets Claude work directly on your Windows machine — reading files, running commands, managing projects — without you acting as the middleman.

---

## What is this, exactly?

local-terminal-mcp is a small program that runs quietly in the background on your Windows PC. Once it's running, Claude can see your files, run commands, and help you build and manage projects directly — instead of just telling you what to type.

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
- Connect to the internet from your machine
- Run anything destructive without your explicit confirmation

See [COMMANDS.md](COMMANDS.md) for the full breakdown.

---

## What you'll need before you start

Before installing, make sure you have:

- **Windows 10 or Windows 11** — this plugin is Windows-only
- **A Claude account** — either [Claude.ai](https://claude.ai) or [Claude Desktop](https://claude.ai/download) (the desktop app)
- **Node.js installed** — this is what runs the plugin. Download it free at [nodejs.org](https://nodejs.org) — get the LTS version (the one that says "Recommended For Most Users")
- **An Anthropic API key** — needed for the security layer that evaluates commands before Claude runs them. Get one at [console.anthropic.com](https://console.anthropic.com) → API Keys → Create new key. You'll need to add a small amount of credit (a few dollars goes a long way).
- **A ForgeRift subscription** — you'll get an auth token by email after subscribing at [forgerift.io](https://forgerift.io)

**Not sure if Node.js is installed?** Open PowerShell and type `node --version`. If you see a number like `v20.11.0`, you're good. If you get an error, download it from nodejs.org first.

---

## Step-by-step setup

### Step 1 — Download the plugin

Open PowerShell **as Administrator** (right-click PowerShell → "Run as administrator") and run:

```powershell
git clone https://github.com/ForgeRift/local-terminal-mcp
cd local-terminal-mcp
```

If you don't have `git`, download it from [git-scm.com](https://git-scm.com) and restart PowerShell after installing.

---

### Step 2 — Run the installer

Still in the same Administrator PowerShell window:

```powershell
.\setup.ps1
```

The installer will:
- Build the plugin (takes about 30 seconds)
- Generate a secure auth token and save it to a `.env` file
- Install the plugin as a Windows Service (so it starts automatically when you boot)
- Print a snippet of config text for you to copy

**You should see something like this at the end:**
```
✓ Service installed and started
✓ Auth token saved to .env

Add this to your Claude Desktop config:
{
  "mcpServers": {
    "local-terminal": {
      ...
    }
  }
}
```

Copy that entire snippet — you'll need it in the next step.

---

### Step 3 — Add your ForgeRift auth token

Open the `.env` file in the `local-terminal-mcp` folder (you can use Notepad). You'll see a line that says:

```
MCP_AUTH_TOKEN=your-token-here
```

Replace `your-token-here` with the token you received in your ForgeRift welcome email. Save the file.

Then add your Anthropic API key on a new line:

```
ANTHROPIC_API_KEY=sk-ant-...
```

Save the file, then restart the service:

```powershell
nssm restart local-terminal-mcp
```

---

### Step 4 — Connect Claude Desktop

Find your Claude Desktop config file at:
```
%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\claude_desktop_config.json
```

Open it in Notepad and paste the snippet from Step 2 inside the `mcpServers` section. If the file is empty or new, paste this entire thing:

```json
{
  "mcpServers": {
    "local-terminal": {
      "command": "node",
      "args": ["C:\\path\\to\\local-terminal-mcp\\dist\\index.js"],
      "env": {
        "MCP_AUTH_TOKEN": "your-token-here"
      }
    }
  }
}
```

Replace the path and token with your actual values (the installer printed the exact snippet — use that).

**Restart Claude Desktop** after saving.

---

### Step 5 — Verify it's working

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
- "Pull the latest changes, install dependencies, and tell me if the build passes"
- "Find every TODO comment across my project and summarize them"
- "Look at my git log and write a summary of what changed this week"
- "Run my test suite and show me which tests are failing"

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
- *"I'm looking at this GitHub PR — pull it locally and run the tests."* Claude reads the PR URL from your browser, gets the branch name, and runs `git fetch` + `git checkout` + `npm test` on your machine.
- *"This error is showing in my browser console — find where it's coming from in my code."* Claude reads the browser error, searches your local project for the source.
- *"Walk me through what this dependency does"* while you have its npm page open — Claude reads the page and cross-references it against your `package.json`.

Claude in Chrome is available as a beta from [claude.ai](https://claude.ai). Install it, connect it, and it will appear as a tool in the same conversation where local-terminal-mcp is active.

---

*Built by [ForgeRift LLC](https://forgerift.io) · [forgerift.io](https://forgerift.io)*

---

## Set Up Claude as Your Plugin Expert (Recommended)

Claude works even better when it already knows how local-terminal-mcp works — which tools are available, what commands are blocked on Windows, and what to check when something goes wrong. This step primes Claude with that knowledge so it can self-diagnose common issues and give you accurate guidance.

**Pick one option:**

### Option A: Claude Project (best for ongoing use)
1. In Claude, go to **Projects** and open or create a project for your local machine work
2. Add **[CLAUDE_CONTEXT.md](CLAUDE_CONTEXT.md)** as a project file
3. Every conversation in that project automatically has full plugin context

### Option B: Add to Claude Memory
Start a new Claude conversation and paste:

> *"Please remember the following about my local-terminal-mcp setup: [paste the contents of CLAUDE_CONTEXT.md]. Reference this any time I ask about my local machine, files, or my ForgeRift plugin."*

### Option C: Paste at Session Start
Paste the contents of [CLAUDE_CONTEXT.md](CLAUDE_CONTEXT.md) at the start of any troubleshooting session. Claude will use it for that conversation.

---

**What CLAUDE_CONTEXT.md contains:** all 8 tools and what they do, the full RED/AMBER/GREEN security model with 450+ blocked patterns by category, common Windows gotchas, configuration reference, and log file locations.

Once loaded, try:
> *"I’m having trouble with [describe issue]. What’s the most likely cause given how local-terminal-mcp works?"*
