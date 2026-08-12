package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/vtmattedi/mw-oauth-service/internal/admin"
	"github.com/vtmattedi/mw-oauth-service/internal/store/sqlite"
)

func main() {
	emailFlag := flag.String(
		"email",
		"",
		"administrator email address",
	)
	dbFlag := flag.String(
		"db",
		"",
		"SQLite database path (defaults to DATABASE_PATH)",
	)
	flag.Parse()

	dbPath := strings.TrimSpace(*dbFlag)
	if dbPath == "" {
		dbPath = strings.TrimSpace(os.Getenv("DATABASE_PATH"))
	}
	if dbPath == "" {
		dbPath = "./data/oauth.db"
	}

	email := strings.ToLower(strings.TrimSpace(*emailFlag))
	if email == "" {
		fmt.Print("Admin email: ")
		reader := bufio.NewReader(os.Stdin)
		value, err := reader.ReadString('\n')
		if err != nil {
			fatal("read email", err)
		}
		email = strings.ToLower(strings.TrimSpace(value))
	}
	if email == "" || !strings.Contains(email, "@") {
		fatalMessage("a valid admin email is required")
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		fatalMessage(
			"password input requires an interactive TTY; " +
				"run this command with -it inside Docker",
		)
	}

	fmt.Print("Password: ")
	passwordBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fatal("read password", err)
	}

	fmt.Print("Confirm password: ")
	confirmBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		fatal("read password confirmation", err)
	}

	password := string(passwordBytes)
	confirm := string(confirmBytes)

	if len(password) < 12 {
		fatalMessage("password must be at least 12 characters")
	}
	if password != confirm {
		fatalMessage("password confirmation does not match")
	}

	passwordHash, err := admin.HashPassword(password)
	if err != nil {
		fatal("hash password", err)
	}

	store, err := sqlite.Open(dbPath)
	if err != nil {
		fatal("open database", err)
	}
	defer store.Close()

	ctx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	user, err := store.CreateAdminUser(
		ctx,
		email,
		passwordHash,
	)
	if err != nil {
		fatal("create admin user", err)
	}

	fmt.Printf(
		"Created admin user id=%d email=%s\n",
		user.ID,
		user.Email,
	)
}

func fatal(action string, err error) {
	fmt.Fprintf(os.Stderr, "ERROR: %s: %v\n", action, err)
	os.Exit(1)
}

func fatalMessage(message string) {
	fmt.Fprintf(os.Stderr, "ERROR: %s\n", message)
	os.Exit(1)
}
