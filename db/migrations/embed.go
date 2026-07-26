// Package migrations embeds the SQL migration files so they ship inside the
// migrate binary and no golang-migrate CLI install is required.
package migrations

import "embed"

//go:embed *.sql
var FS embed.FS
