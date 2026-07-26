// Command migrate applies the embedded SQL migrations to Neon.
// Usage: migrate [up|down|version] — reads DATABASE_URL_UNPOOLED (falls back to
// DATABASE_URL). Migrations MUST run against the direct (unpooled) Neon URL
// because PgBouncer transaction pooling breaks advisory locks and DDL sessions.
package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"

	migrations "github.com/ownspce/backend/db/migrations"
	"github.com/ownspce/backend/internal/dotenv"
)

func main() {
	dotenv.Load(".env")

	cmd := "up"
	if len(os.Args) > 1 {
		cmd = os.Args[1]
	}

	dsn := os.Getenv("DATABASE_URL_UNPOOLED")
	if dsn == "" {
		dsn = os.Getenv("DATABASE_URL")
	}
	if dsn == "" {
		log.Fatal("DATABASE_URL_UNPOOLED or DATABASE_URL must be set")
	}

	src, err := iofs.New(migrations.FS, ".")
	if err != nil {
		log.Fatalf("load migrations: %v", err)
	}

	m, err := migrate.NewWithSourceInstance("iofs", src, dsn)
	if err != nil {
		log.Fatalf("open migrator: %v", err)
	}
	defer m.Close()

	switch cmd {
	case "up":
		err = m.Up()
	case "down":
		err = m.Steps(-1)
	case "version":
		v, dirty, verr := m.Version()
		if verr != nil {
			log.Fatalf("version: %v", verr)
		}
		fmt.Printf("version=%d dirty=%t\n", v, dirty)
		return
	default:
		log.Fatalf("unknown command %q (want up|down|version)", cmd)
	}

	if err != nil && !errors.Is(err, migrate.ErrNoChange) {
		log.Fatalf("%s: %v", cmd, err)
	}
	log.Printf("migrate %s: ok", cmd)
}
