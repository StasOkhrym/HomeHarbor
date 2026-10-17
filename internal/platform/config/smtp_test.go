package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSMTPConfigOptionalAndSelectedSecret(t *testing.T) {
	absent := func(string) (string, bool) { return "", false }

	disabled := writeConfig(
		t,
		validControlFile(
			"\n[smtp]\nenabled=false\npassword_file='/definitely/missing/mail-secret'\nca_file='/definitely/missing/mail-ca'\n",
		),
	)

	cfg, err := LoadControl(Sources{File: disabled, Env: absent})

	if err != nil || cfg.SMTP.Enabled {
		t.Fatal("disabled SMTP opened unrelated credentials", err)
	}

	password := filepath.Join(t.TempDir(), "smtp-password")

	if err := os.WriteFile(password, []byte("smtp-private\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	settings := fmt.Sprintf(
		"\n[smtp]\nenabled=true\nhost='smtp.example.test'\nusername='homeharbor'\nfrom='homeharbor@example.test'\npassword_file=%q\n",
		password,
	)

	path := writeConfig(t, validControlFile(settings))

	cfg, err = LoadControl(Sources{File: path, Env: absent})
	if err != nil {
		t.Fatal(err)
	}

	if cfg.SMTP.Password != "smtp-private" || cfg.SMTP.Mode != "starttls" || cfg.SMTP.Port != 587 ||
		cfg.SMTP.Timeout != 10*time.Second {
		t.Fatal("SMTP defaults or secret source incorrect")
	}

	cfg, err = LoadControl(Sources{File: path, Env: func(name string) (string, bool) {
		if name == "HOMEHARBOR_SMTP_PASSWORD" {
			return "environment-private", true
		}

		return "", false
	}})

	if err != nil || cfg.SMTP.Password != "environment-private" {
		t.Fatal("explicit SMTP environment did not win", err)
	}
}

func TestSMTPConfigRejectsUnsafeSubmission(t *testing.T) {
	base := "\n[smtp]\nenabled=true\nhost='smtp.example.test'\nusername='private-user'\npassword='private-password'\nfrom='homeharbor@example.test'\n"
	for _, change := range []string{"mode='plaintext'", "mode=''", "timeout='0s'", "timeout='31s'", "port=0"} {
		t.Run(change, func(t *testing.T) {
			path := writeConfig(t, validControlFile(base+change+"\n"))

			_, err := LoadControl(
				Sources{File: path, Env: func(string) (string, bool) { return "", false }},
			)

			if err == nil {
				t.Fatal("unsafe SMTP configuration admitted")
			}
			if strings.Contains(err.Error(), "private-user") ||
				strings.Contains(err.Error(), "private-password") {
				t.Fatal("configuration diagnostic exposed SMTP credentials")
			}
		})
	}
}

func TestDatabaseRoleIgnoresSMTPSecrets(t *testing.T) {
	path := writeConfig(
		t,
		validControlFile(
			"\n[smtp]\nenabled=true\npassword_file='/definitely/missing/mail-secret'\n",
		),
	)

	if _, err := LoadDatabase(
		Sources{File: path, Env: func(string) (string, bool) { return "", false }},
	); err != nil {
		t.Fatal("migration attempted to initialize SMTP", err)
	}
}
