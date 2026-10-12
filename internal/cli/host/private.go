package host

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// ReadPrivateLine reads one bounded secret from the command's input. Terminal
// input is hidden; redirected input permits explicit scripted manual flows.
// The caller owns the scanner so consecutive lines retain buffered input.
func ReadPrivateLine(scanner *bufio.Scanner, command *cobra.Command, label string) (string, error) {
	if _, err := fmt.Fprintf(command.ErrOrStderr(), "%s (stdin): ", label); err != nil {
		return "", err
	}

	if input, ok := command.InOrStdin().(*os.File); ok && term.IsTerminal(int(input.Fd())) {
		private, err := term.ReadPassword(int(input.Fd()))
		_, _ = fmt.Fprintln(command.ErrOrStderr())
		if err != nil {
			return "", fmt.Errorf("read private input: %w", err)
		}
		if len(private) > 16*1024 {
			return "", errors.New("private input is too long")
		}

		value := strings.TrimSpace(string(private))
		if value == "" {
			return "", errors.New("private input is empty")
		}

		return value, nil
	}

	if !scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return "", fmt.Errorf("read private input: %w", err)
		}

		return "", errors.New("private input is incomplete")
	}

	value := strings.TrimSpace(scanner.Text())
	if value == "" {
		return "", errors.New("private input is empty")
	}

	return value, nil
}
