package config

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the application configuration.
type Config struct {
	LLM      LLMConfig      `yaml:"llm"`
	Database DatabaseConfig `yaml:"database"`
	Defaults DefaultsConfig `yaml:"defaults"`
	Server   ServerConfig   `yaml:"server"`
}

// LLMConfig contains settings for LLM integration.
type LLMConfig struct {
	Provider       string `yaml:"provider"`
	Model          string `yaml:"model"`
	APIKey         string `yaml:"api_key"`
	Endpoint       string `yaml:"endpoint"`
	Timeout        int    `yaml:"timeout"`
	MaxCandidates  int    `yaml:"max_candidates"`
	PromptTemplate string `yaml:"prompt_template"`
}

// DatabaseConfig contains database paths and settings.
type DatabaseConfig struct {
	DbsDir    string `yaml:"dbs_dir"`
	ScoringDb string `yaml:"scoring_db"`
}

// DefaultsConfig contains default values for rule generation.
type DefaultsConfig struct {
	Author            string `yaml:"author"`
	MinStringLength   int    `yaml:"min_string_length"`
	MaxStringLength   int    `yaml:"max_string_length"`
	MinScore          int    `yaml:"min_score"`
	HighScoreThresh   int    `yaml:"high_score_threshold"`
	MaxStringsPerRule int    `yaml:"max_strings_per_rule"`
	SuperRuleOverlap  int    `yaml:"super_rule_overlap"`
	FilesizeMultiply  int    `yaml:"filesize_multiplier"`
	IncludeOpcodes    bool   `yaml:"include_opcodes"`
	NumOpcodes        int    `yaml:"num_opcodes"`
}

// ServerConfig contains web server settings.
type ServerConfig struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
}

// DefaultConfig returns a new Config with default values.
func DefaultConfig() *Config {
	cfg := &Config{
		LLM: LLMConfig{
			Provider:       "",
			Model:          "",
			APIKey:         "",
			Endpoint:       "",
			Timeout:        60,
			MaxCandidates:  500,
			PromptTemplate: "",
		},
		Database: DatabaseConfig{
			DbsDir:    "./dbs",
			ScoringDb: "~/.yargen/scoring.db",
		},
		Defaults: DefaultsConfig{
			Author:            "yarGen",
			MinStringLength:   8,
			MaxStringLength:   128,
			MinScore:          0,
			HighScoreThresh:   30,
			MaxStringsPerRule: 20,
			SuperRuleOverlap:  5,
			FilesizeMultiply:  3,
			IncludeOpcodes:    true,
			NumOpcodes:        3,
		},
		Server: ServerConfig{
			Host: "127.0.0.1",
			Port: 8080,
		},
	}
	cfg.Database.DbsDir = expandPath(cfg.Database.DbsDir)
	cfg.Database.ScoringDb = expandPath(cfg.Database.ScoringDb)
	return cfg
}

// Load reads and parses a configuration file from the given path.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	
	expanded := expandPath(path)
	data, err := os.ReadFile(expanded)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return nil, err
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}

	cfg.LLM.APIKey = expandEnvVars(cfg.LLM.APIKey)
	cfg.Database.DbsDir = expandPath(cfg.Database.DbsDir)
	cfg.Database.ScoringDb = expandPath(cfg.Database.ScoringDb)

	return cfg, nil
}

// LoadDefault loads the config from the first available location in the standard paths.
// Checks in order: ./config/config.yaml, ~/.yargen/config.yaml, ~/.yargen/config.yml
func LoadDefault() (*Config, error) {
	return Load(FindConfigPath())
}

// Save writes the configuration to a file at the given path.
func (c *Config) Save(path string) error {
	expanded := expandPath(path)
	dir := filepath.Dir(expanded)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data, err := yaml.Marshal(c)
	if err != nil {
		return err
	}

	return os.WriteFile(expanded, data, 0644)
}

// FindConfigPath tries to find a config file in standard locations.
// Returns the first existing path, or the default path if none exist.
// Checks in order: ./config/config.yaml, ~/.yargen/config.yaml, ~/.yargen/config.yml
func FindConfigPath() string {
	paths := []string{
		"./config/config.yaml",  // New default: project directory
		"~/.yargen/config.yaml", // Legacy: home directory (YAML)
		"~/.yargen/config.yml",  // Legacy: home directory (YML)
	}

	for _, path := range paths {
		expanded := expandPath(path)
		if _, err := os.Stat(expanded); err == nil {
			return path
		}
	}

	// Return default if none found
	return paths[0]
}

// DefaultConfigPath returns the default config path, checking standard locations first.
// This maintains backward compatibility - checks ./config/config.yaml first, then ~/.yargen/config.yaml
func DefaultConfigPath() string {
	return FindConfigPath()
}

func expandPath(path string) string {
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}
	return path
}

var envVarPattern = regexp.MustCompile(`\$\{([^}]+)\}`)

func expandEnvVars(s string) string {
	return envVarPattern.ReplaceAllStringFunc(s, func(match string) string {
		varName := match[2 : len(match)-1]
		if val := os.Getenv(varName); val != "" {
			return val
		}
		return match
	})
}
