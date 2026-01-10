# Step-by-Step Setup Guide

This guide will walk you through installing and configuring yarGen-Go from scratch.

## Step 1: Prerequisites

**Required:**
- **Go 1.22 or later** - [Download Go](https://go.dev/dl/)
- **GCC compiler** - Required for SQLite (CGO)

**Linux (Ubuntu/Debian):**
```bash
sudo apt-get update
sudo apt-get install build-essential gcc
```

**macOS:**
```bash
# Install Xcode Command Line Tools
xcode-select --install
```

**Windows:**
- Install [MinGW-w64](https://www.mingw-w64.org/downloads/) or [TDM-GCC](https://jmeubank.github.io/tdm-gcc/)
- Ensure `gcc` is in your PATH

## Step 2: Clone and Build

```bash
# Clone the repository
git clone https://github.com/Neo23x0/yarGen-Go.git
cd yarGen-Go

# Download dependencies
go mod tidy

# Build binaries
go build -o yargen ./cmd/yargen
go build -o yargen-util ./cmd/yargen-util

# Verify build
./yargen --help
./yargen-util --help
```

**Alternative: Using Make (if available):**
```bash
make build        # Build for current platform
make install      # Install to GOPATH/bin
```

## Step 3: Download Goodware Databases

The goodware database is essential for filtering out common strings found in legitimate software.

```bash
# Download built-in databases (~913 MB)
./yargen-util update

# Verify databases
./yargen-util list
```

This will create a `dbs/` directory with the goodware databases. The first download may take several minutes depending on your connection.

## Step 4: Configuration Directory

The config directory (`./config/`) already exists in the project. The configuration file will be created in Step 5 by copying the example file to `./config/config.yaml`.

**Note:** If you prefer to use a config file in your home directory instead, you can create `~/.yargen/` and use the `--config` flag when running yarGen.

## Step 5: Configure LLM (Optional but Recommended)

LLM integration improves string selection quality. The easiest way to set up configuration is to copy the example file.

1. **Copy the example configuration:**
   
   The default config location is `./config/config.yaml` in the project directory. Copy the example file there:
   
   **Linux / macOS:**
   ```bash
   cp config/config.example.yml config/config.yaml
   ```
   
   **Windows (PowerShell):**
   ```powershell
   Copy-Item -Path "config\config.example.yml" -Destination "config\config.yaml"
   ```
   
   **Windows (Command Prompt):**
   ```cmd
   copy config\config.example.yml config\config.yaml
   ```
   
   **Note:** If you prefer to use a config file in your home directory instead (e.g., `~/.yargen/config.yml`), you can copy it there and use the `--config` flag: `./yargen serve --config ~/.yargen/config.yml`

2. **Edit the config file** to match your LLM provider:
   
   Open `config/config.yaml` in your project directory and adjust:

   **For OpenAI:**
   ```yaml
   llm:
     provider: "openai"
     model: "gpt-4o-mini"  # or gpt-4o, gpt-4-turbo
     api_key: "${OPENAI_API_KEY}"
   ```
   
   **For Anthropic:**
   ```yaml
   llm:
     provider: "anthropic"
     model: "claude-sonnet-4-20250514"  # or claude-opus-4-20250514
     api_key: "${ANTHROPIC_API_KEY}"
   ```
   
   **For Google Gemini:**
   ```yaml
   llm:
     provider: "gemini"
     model: "gemini-1.5-pro"  # or gemini-1.5-flash
     api_key: "${GEMINI_API_KEY}"
   ```
   
   **For Ollama (Local):**
   ```yaml
   llm:
     provider: "ollama"
     model: "llama3.3"  # or llama3.2, qwen2.5, mistral
     endpoint: "http://localhost:11434"
     api_key: ""  # Not needed for local
   ```

3. **Set your API key as an environment variable:**
   
   The config file uses `${VARIABLE_NAME}` syntax to read from environment variables.
   
   **Linux / macOS:**
   ```bash
   # For OpenAI
   export OPENAI_API_KEY="sk-your-key-here"
   
   # For Anthropic
   export ANTHROPIC_API_KEY="sk-ant-your-key-here"
   
   # For Gemini
   export GEMINI_API_KEY="your-gemini-key-here"
   
   # Add to ~/.bashrc or ~/.zshrc for persistence:
   echo 'export OPENAI_API_KEY="sk-your-key-here"' >> ~/.bashrc
   ```
   
   **Windows (PowerShell):**
   ```powershell
   # For OpenAI
   $env:OPENAI_API_KEY="sk-your-key-here"
   
   # For Anthropic
   $env:ANTHROPIC_API_KEY="sk-ant-your-key-here"
   
   # For Gemini
   $env:GEMINI_API_KEY="your-gemini-key-here"
   
   # Permanent:
   [System.Environment]::SetEnvironmentVariable("OPENAI_API_KEY", "sk-your-key-here", "User")
   ```
   
   **Windows (Command Prompt):**
   ```cmd
   set OPENAI_API_KEY=sk-your-key-here
   REM Or set permanently via System Properties → Environment Variables
   ```

4. **Get API Keys (if needed):**
   - **OpenAI:** [platform.openai.com/api-keys](https://platform.openai.com/api-keys)
   - **Anthropic:** [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys)
   - **Google Gemini:** [aistudio.google.com/app/apikey](https://aistudio.google.com/app/apikey)
   - **Ollama:** No API key needed for local installation. Install from [ollama.com](https://ollama.com) and run `ollama pull llama3.3`

The example config file (`config/config.example.yml`) contains detailed comments explaining all options and model choices for each provider.

## Step 6: First-Time Usage

### Test CLI Mode

```bash
# Create a test malware directory
mkdir test-malware
# Add some sample files (PE executables, etc.)

# Generate rules
./yargen -m ./test-malware -o test-rules.yar

# With LLM refinement
./yargen -m ./test-malware -o test-rules.yar --opcodes
```

### Test Web UI

```bash
# Start web server
./yargen serve

# Or on custom port
./yargen serve --port 3000
```

Then open http://127.0.0.1:8080 in your browser.

**Web UI Features:**
- Drag & drop malware samples
- Configure generation options
- View generated rules
- Manage scoring rules
- Check LLM configuration status

## Step 7: Verify Installation

```bash
# Check version/build info
./yargen --version

# Test database loading
./yargen-util list

# Verify config loading (will use defaults if config doesn't exist)
./yargen -m ./test-malware --debug
```

## Troubleshooting

**Build Issues:**
- **CGO errors**: Ensure GCC is installed and in PATH
- **Go version**: Update to Go 1.22+ if you see version errors
- **Permission denied**: On Linux/macOS, you may need `chmod +x yargen yargen-util`

**Database Issues:**
- **Download fails**: Check internet connection, retry with `./yargen-util update`
- **Database not found**: Ensure you ran `./yargen-util update` and `dbs/` directory exists

**LLM Issues:**
- **API key not found**: Verify environment variable is set (use `echo $OPENAI_API_KEY` or `$env:OPENAI_API_KEY` in PowerShell)
- **Connection errors**: Check API key validity, network connectivity, and firewall settings
- **Config not loading**: Verify config file location (default is `./config/config.yaml` in project directory, or use `--config` flag to specify a different path)

**Memory Issues:**
- If you get out-of-memory errors, reduce `max_candidates` in config
- Disable opcodes with `--no-opcodes` flag to reduce memory usage
- Consider using a smaller LLM model

## Installation (Alternative Methods)

### Using Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/Neo23x0/yarGen-Go/releases) page for your platform.

### Using Go Install

```bash
go install github.com/Neo23x0/yarGen-Go/cmd/yargen@latest
go install github.com/Neo23x0/yarGen-Go/cmd/yargen-util@latest
```

Binaries will be installed to `$GOPATH/bin` or `$HOME/go/bin` (add to PATH if needed).
