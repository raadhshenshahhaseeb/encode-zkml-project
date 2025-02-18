package config

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
)

type Config interface {
	GetConfig() *config
}

type config struct {
	Chain struct {
		PrivateKey string `mapstructure:"PRIVATE_KEY" json:"chain"`
		Endpoint   string `mapstructure:"ENDPOINT" json:"endpoint"`
	} `mapstructure:"CHAIN" json:"chain"`
	Contracts struct {
		PROVER struct {
			Address string      `mapstructure:"ADDRESS" json:"address"`
			ABI     interface{} `mapstructure:"ABI" json:"abi"`
		} `mapstructure:"PROVER" json:"prover"`
		Verifier struct {
			Address string      `mapstructure:"ADDRESS" json:"address"`
			ABI     interface{} `mapstructure:"ABI" json:"abi"`
		} `mapstructure:"Verifier" json:"Verifier"`
	} `mapstructure:"CONTRACTS" json:"contracts"`
	Logger struct {
		Level int    `mapstructure:"LEVEL" json:"level"`
		Env   string `mapstructure:"ENV" json:"env"`
	} `mapstructure:"LOGGER" json:"logger"`
	Server struct {
		Host    string `mapstructure:"HOST" json:"host"`
		PORT    string `mapstructure:"PORT" json:"port"`
		CORSAGE int    `mapstructure:"CORS_AGE" json:"cors"`
	} `mapstructure:"SERVER" json:"server"`
	JWT struct {
		Secret string `mapstructure:"SECRET" json:"secret"`
		Issuer string `mapstructure:"ISSUER" json:"issuer"`
		Expiry int64  `mapstructure:"EXPIRY" json:"expiry"`
	} `mapStructure:"JWT" json:"jwt"`
}

func Init() (Config, error) {
	wd, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("failed to get working directory: %v", err)
	}
	
	// Go up directory levels until we find go.mod to determine project root
	projectRoot := wd
	for {
		if _, err := os.Stat(filepath.Join(projectRoot, "go.mod")); err == nil {
			break
		}
		parent := filepath.Dir(projectRoot)
		if parent == projectRoot {
			return nil, fmt.Errorf("could not find project root (no go.mod found)")
		}
		projectRoot = parent
	}

	configPath := filepath.Join(projectRoot, "env.json")
	sampleConfigPath := filepath.Join(projectRoot, "sample.env.json")

	// Check if env.json exists, if not create it from sample.env.json.
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		if _, err := os.Stat(sampleConfigPath); err == nil {
			err := copyFile(sampleConfigPath, configPath)
			if err != nil {
				return nil, fmt.Errorf("failed to create env.json from sample: %w", err)
			}
			//TODO: Add a logger here.
			fmt.Println("env.json created from sample.env.json")
		} else {
			return nil, fmt.Errorf("sample.env.json not found, cannot create env.json")
		}
	}

	viper.SetConfigFile(configPath)
	viper.AutomaticEnv()

	err = viper.ReadInConfig()
	if err != nil {
		return nil, fmt.Errorf("error discovering config: %w", err)
	}

	conf := config{}
	err = viper.Unmarshal(&conf)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling config: %w", err)
	}

	return &conf, nil
}

// Helper function to copy file
func copyFile(src, dst string) error {
	sourceFile, err := os.Open(src)
	if err != nil {
		return err
	}
	defer sourceFile.Close()

	destinationFile, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer destinationFile.Close()

	_, err = io.Copy(destinationFile, sourceFile)
	return err
}

func (c *config) GetConfig() *config {
	return c
}
