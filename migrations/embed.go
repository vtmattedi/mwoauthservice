package migrations

import "embed"

// Files contains SQL migrations embedded into the service binary.
//
//go:embed *.sql
var Files embed.FS
