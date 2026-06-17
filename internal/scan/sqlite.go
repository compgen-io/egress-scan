package scan

import (
	"database/sql"
	"fmt"
	"os"

	_ "modernc.org/sqlite" // pure-Go SQLite driver (no CGo)
)

// scanSQLite opens a SQLite database and scans every TEXT/BLOB cell across all
// user tables. A structured read is required because string content can live in
// overflow pages where a raw byte scan would miss or fragment it.
//
// modernc.org/sqlite is pure Go, so this keeps the default binary static. The
// DB is written to a temp file because the driver opens a file path.
func (s *Scanner) scanSQLite(name string, data []byte, res *Result) {
	tmp, err := os.CreateTemp("", "egress-scan-*.sqlite")
	if err != nil {
		s.markErr(name, res, "sqlite temp: "+err.Error())
		return
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		s.markErr(name, res, "sqlite write: "+err.Error())
		return
	}
	tmp.Close()

	// Read-only, immutable: don't create -wal/-shm sidecars or mutate the file.
	dsn := fmt.Sprintf("file:%s?mode=ro&immutable=1", tmp.Name())
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		s.markErr(name, res, "sqlite open: "+err.Error())
		return
	}
	defer db.Close()

	tables, err := listTables(db)
	if err != nil {
		s.markErr(name, res, "sqlite schema: "+err.Error())
		return
	}

	for _, t := range tables {
		if err := s.scanSQLiteTable(db, name, t, res); err != nil {
			s.markErr(name, res, fmt.Sprintf("sqlite table %q: %v", t, err))
		}
	}
	res.Stats.Scanned++
}

func listTables(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		tables = append(tables, n)
	}
	return tables, rows.Err()
}

// scanSQLiteTable selects all rows and scans every column value as text. Column
// names are scanned too, since a key/header can itself be an IB-ID.
func (s *Scanner) scanSQLiteTable(db *sql.DB, dbName, table string, res *Result) error {
	rows, err := db.Query(`SELECT * FROM "` + table + `"`)
	if err != nil {
		return err
	}
	defer rows.Close()

	cols, err := rows.Columns()
	if err != nil {
		return err
	}
	for _, c := range cols {
		for id := range s.cfg.Matcher.IBIDs(c) {
			res.record(dbName, id, "sqlite", "structured")
		}
	}

	vals := make([]any, len(cols))
	ptrs := make([]any, len(cols))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	rowCount := 0
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			return err
		}
		rowCount++
		for _, v := range vals {
			var text string
			switch tv := v.(type) {
			case string:
				text = tv
			case []byte:
				text = string(tv)
			default:
				continue
			}
			for id := range s.cfg.Matcher.IBIDs(text) {
				res.record(dbName, id, "sqlite", "structured")
			}
			res.PHIMatches += s.cfg.Matcher.PHICount(text)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	res.addGrid(dbName, "sqlite", rowCount, len(cols))
	return nil
}
