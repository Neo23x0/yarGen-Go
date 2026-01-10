![yarGen-Go](./images/yargen-go-logo.png)

# yarGen-Go

A Go rewrite of [yarGen](https://github.com/Neo23x0/yarGen) - an automatic YARA rule generator.

## Overview

yarGen-Go generates YARA rules from strings found in malware files while removing all strings that also appear in goodware files. It includes:

- **yargen** - Main rule generator (CLI + web server)
- **yargen-util** - Database management utility

## Getting Started

**Linux/macOS:**

1. **Prerequisites:** Install Go 1.22+
2. **Build:** Clone repository or download the ZIP and extract it
3. **Build binaries:** Run the following commands:
   ```bash
   go mod tidy
   go build -o yargen ./cmd/yargen
   go build -o yargen-util ./cmd/yargen-util
   ```
4. **Databases:** Run `./yargen-util update` to download goodware databases
5. **Configure (Optional):** Copy `config/config.example.yml` to `config/config.yaml` and set your LLM API key
6. **Use:** Run `./yargen serve` and open the Web UI at [http://127.0.0.1:8080](http://127.0.0.1:8080)

**Windows:**

1. **Prerequisites:** Install Go 1.22+
2. **Build:** Clone repository or download the ZIP and extract it
3. **Build binaries:** Run the following commands:
   ```powershell
   go mod tidy
   go build -o yargen.exe .\cmd\yargen
   go build -o yargen-util.exe .\cmd\yargen-util
   ```
4. **Databases:** Run `yargen-util.exe update` to download goodware databases
5. **Configure (Optional):** Copy `.\config\config.example.yml` to `.\config\config.yaml` and set your LLM API key
6. **Use:** Run `yargen.exe serve` and open the Web UI at [http://127.0.0.1:8080](http://127.0.0.1:8080)

📖 **For detailed setup instructions, see the [Step-by-Step Setup Guide](docs/SETUP.md)**

## Features

- ASCII and UTF-16LE (wide) string extraction
- Opcode extraction from PE/ELF executables
- Encoding detection: Base64, hex-encoded, reversed strings
- Magic header and filesize conditions
- Super rule generation (overlapping string patterns across files)
- Customizable scoring rules (SQLite-backed, editable via Web UI)
- **Efficient LLM integration** for string selection (OpenAI, Anthropic, Gemini, Ollama)
  - Only submits prefiltered top candidates (no goodware strings, max 500 from automatic evaluation)
  - Requests numbered list instead of full strings to minimize token usage
  - Significantly reduces API costs compared to naive approaches
- Web UI for rule generation and scoring rules management

## Installation (Alternative Methods)

### Using Pre-built Binaries

Download pre-built binaries from the [Releases](https://github.com/Neo23x0/yarGen-Go/releases) page for your platform.

### Using Go Install

```bash
go install github.com/Neo23x0/yarGen-Go/cmd/yargen@latest
go install github.com/Neo23x0/yarGen-Go/cmd/yargen-util@latest
```

Binaries will be installed to `$GOPATH/bin` or `$HOME/go/bin` (add to PATH if needed).

## Usage

### CLI Mode

```bash
# Basic usage
yargen -m ./malware-samples

# With options
yargen -m ./malware-samples \
    -o rules.yar \
    -a "Your Name" \
    -r "Internal Research" \
    --opcodes \
    --score

# Show all options
yargen -h
```

### Web UI Mode

```bash
# Start web server on localhost:8080
yargen serve

# Custom port
yargen serve --port 3000
```

Then open http://127.0.0.1:8080 in your browser.

### Database Management

```bash
# Download built-in databases from GitHub
yargen-util update

# List all databases
yargen-util list

# Create new goodware database
yargen-util create -g /path/to/goodware -i mydb

# Append to existing database
yargen-util append -g /path/to/more/goodware -i mydb

# Inspect database
yargen-util inspect ./dbs/good-strings-mydb.db

# Merge databases
yargen-util merge -o combined.db db1.db db2.db
```

## Configuration

**Default Config Location:**
- The default config file is `./config/config.yaml` (in the project directory)
- For backward compatibility, the application will automatically check `~/.yargen/config.yaml` or `~/.yargen/config.yml` if the default location doesn't exist
- Use the `--config` flag to specify a different config file path
- Example: `./yargen serve --config /path/to/custom/config.yml`

**Quick Setup:** 
1. Copy the example config: `cp config/config.example.yml config/config.yaml` (see [Step 5 in the Setup Guide](docs/SETUP.md#step-5-configure-llm-optional-but-recommended) for details)
2. Edit the file to match your LLM provider
3. Set your API key as an environment variable

**Example Configuration** (from `config/config.example.yml`):

```yaml
llm:
  provider: "openai"  # openai, anthropic, gemini, ollama
  model: "gpt-4o-mini"
  api_key: "${OPENAI_API_KEY}"  # Uses environment variable
  endpoint: ""  # For ollama: http://localhost:11434
  timeout: 60
  max_candidates: 500

database:
  dbs_dir: "./dbs"
  scoring_db: "~/.yargen/scoring.db"

defaults:
  author: "yarGen"
  min_string_length: 8
  max_string_length: 128
  min_score: 0
  max_strings: 20
  super_rule_overlap: 5
  filesize_multiplier: 3
  include_opcodes: true
  num_opcodes: 3

server:
  host: "127.0.0.1"
  port: 8080
```

**Environment Variables:**
The config file supports environment variable expansion using `${VARIABLE_NAME}` syntax. Common variables:
- `OPENAI_API_KEY` - OpenAI API key
- `ANTHROPIC_API_KEY` - Anthropic API key
- `GEMINI_API_KEY` - Google Gemini API key

**Custom Config Location:**
If you prefer to use a config file in your home directory (e.g., `~/.yargen/config.yml`), use the `--config` flag:
```bash
./yargen serve --config ~/.yargen/config.yml
```

See [Step 5 in the Setup Guide](docs/SETUP.md#step-5-configure-llm-optional-but-recommended) for platform-specific environment variable setup instructions.

## CLI Flags

### Rule Creation

| Flag | Description | Default |
|------|-------------|---------|
| `-m` | Path to malware directory | required |
| `-y` | Minimum string length | 8 |
| `-z` | Minimum score threshold | 0 |
| `-x` | High-scoring string threshold | 30 |
| `-w` | Super rule overlap threshold | 5 |
| `-s` | Maximum string length | 128 |
| `-rc` | Max strings per rule | 20 |
| `--excludegood` | Exclude all goodware strings | false<br>*Note: By default, goodware strings receive very low scores but are still included as they can be useful when combined with more specific strings in a malware sample. This flag forces complete removal of all goodware strings from the candidate set.* |
| `--opcodes` | Enable opcode extraction | false |
| `-n` | Number of opcodes to include | 3 |

### Rule Output

| Flag | Description | Default |
|------|-------------|---------|
| `-o` | Output rule file | yargen_rules.yar |
| `-a` | Author name | "yarGen" |
| `-r` | Reference | "" |
| `-l` | License | "" |
| `-p` | Rule description prefix | "" |
| `-b` | Identifier | (folder name) |
| `--score` | Show scores as comments | false |
| `--nosimple` | Skip simple rules in super rules | false |
| `--nomagic` | No magic header condition | false |
| `--nofilesize` | No filesize condition | false |
| `-fm` | Filesize multiplier | 3 |
| `--nosuper` | Disable super rules | false |

### General

| Flag | Description | Default |
|------|-------------|---------|
| `--config` | Config file path | `./config/config.yaml` |
| `--nr` | Non-recursive scan | false |
| `--oe` | Only executable extensions | false |
| `-fs` | Max file size (MB) | 10 |
| `--no-llm` | Disable LLM | false |
| `--debug` | Debug output | false |

## Scoring System

yarGen-Go uses a customizable scoring system to rank extracted strings. Scores accumulate when multiple rules match.

### Built-in Rules (~80 rules)

Categories include:
- **Reductions** (negative scores): `..`, triple spaces, packer strings
- **File paths** (+2 to +4): drive letters, extensions
- **System keywords** (+5): cmd.exe, system32
- **Network** (+3 to +5): protocols, IP addresses
- **Malware keywords** (+5): RAT, spy, inject
- **Encoding** (+5 to +10): Base64, hex-encoded, reversed strings
- **PowerShell** (+4): bypass, encoded commands

### Custom Rules

Manage scoring rules via the Web UI:
- Add/edit/delete rules
- Enable/disable rules
- Import/export as JSON
- Three match types: exact, contains, regex

## Web UI

The Web UI provides:

1. **Generate Page** - Upload files, configure options, generate rules
2. **Scoring Rules Page** - Manage built-in and custom scoring rules
3. **Settings Page** - View LLM configuration status

Features:
- Drag-and-drop file upload
- Real-time rule generation progress
- Download generated .yar files
- CRUD operations for scoring rules
- Import/export scoring rules as JSON

## Memory Requirements

- Minimum: 4 GB RAM
- With opcodes: 8 GB RAM

The goodware database is loaded entirely into memory for O(1) lookups.

## Project Structure

```
yarGen-Go/
├── cmd/
│   ├── yargen/          # Main binary
│   └── yargen-util/     # Database utility
├── docs/
│   └── SETUP.md         # Step-by-step setup guide
├── internal/
│   ├── config/          # YAML configuration
│   ├── database/        # Goodware DB loading/saving
│   ├── extractor/       # String/opcode extraction
│   ├── filter/          # String filtering & scoring
│   ├── llm/             # LLM integration
│   ├── rules/           # YARA rule generation
│   ├── scanner/         # File scanning
│   ├── scoring/         # Scoring engine & SQLite store
│   ├── service/         # Core service layer
│   └── web/             # HTTP server & static files
├── config/
│   └── config.example.yml
├── go.mod
└── README.md
```

## License

Same as the original yarGen project.

## Credits

Based on [yarGen](https://github.com/Neo23x0/yarGen) by Florian Roth.
