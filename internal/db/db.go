// Package db creates and seeds the application's database.
//
// The original runs an embedded H2 instance with Hibernate's
// ddl-auto: create-drop, so the schema is derived from the entity annotations
// at startup and thrown away at shutdown, and import.sql is replayed into the
// fresh schema. This package does the same thing against an in-process SQLite
// database: the DDL below is the schema the entity annotations describe, and
// the seed data is read from the unmodified import.sql.
package db

import (
	"database/sql"
	"fmt"
	"strings"

	_ "modernc.org/sqlite" // registers the pure-Go "sqlite" driver
)

// schema is the DDL Hibernate generates from the @Entity/@Table/@Column
// annotations on model.User and model.Authority, including the USER_SEQ
// sequence the @SequenceGenerator declares. SQLite has no CREATE SEQUENCE, so
// the sequence is a one-row table, which is how it is emulated wherever the
// dialect lacks one.
const schema = `
CREATE TABLE "USER" (
   ID        INTEGER      NOT NULL PRIMARY KEY,
   USERNAME  VARCHAR(50)  UNIQUE,
   PASSWORD  VARCHAR(100),
   FIRSTNAME VARCHAR(50),
   LASTNAME  VARCHAR(50),
   EMAIL     VARCHAR(50),
   ACTIVATED BOOLEAN      NOT NULL
);

CREATE TABLE AUTHORITY (
   NAME VARCHAR(50) NOT NULL PRIMARY KEY
);

CREATE TABLE USER_AUTHORITY (
   USER_ID        INTEGER     NOT NULL,
   AUTHORITY_NAME VARCHAR(50) NOT NULL,
   PRIMARY KEY (USER_ID, AUTHORITY_NAME),
   FOREIGN KEY (USER_ID) REFERENCES "USER" (ID),
   FOREIGN KEY (AUTHORITY_NAME) REFERENCES AUTHORITY (NAME)
);

CREATE TABLE USER_SEQ (
   NEXT_VAL INTEGER NOT NULL
);
INSERT INTO USER_SEQ (NEXT_VAL) VALUES (1);
`

// Open creates a fresh in-memory database, applies the schema, and replays
// importSQL into it. The returned handle is limited to a single connection
// because SQLite gives each connection its own private in-memory database.
func Open(importSQL string) (*sql.DB, error) {
	handle, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		return nil, fmt.Errorf("opening database: %w", err)
	}
	handle.SetMaxOpenConns(1)

	if _, err := handle.Exec(schema); err != nil {
		handle.Close()
		return nil, fmt.Errorf("creating schema: %w", err)
	}
	if err := seed(handle, importSQL); err != nil {
		handle.Close()
		return nil, err
	}
	return handle, nil
}

// seed replays import.sql. The file's first line is an IntelliJ inspection
// pragma beginning with '#'; H2 rejects it and Hibernate logs the failure and
// carries on, so it is skipped here rather than reproduced as an error.
func seed(handle *sql.DB, importSQL string) error {
	transaction, err := handle.Begin()
	if err != nil {
		return fmt.Errorf("starting seed transaction: %w", err)
	}
	defer transaction.Rollback()

	for _, line := range strings.Split(importSQL, "\n") {
		statement := strings.TrimSpace(line)
		if statement == "" || strings.HasPrefix(statement, "#") || strings.HasPrefix(statement, "--") {
			continue
		}
		if _, err := transaction.Exec(statement); err != nil {
			return fmt.Errorf("executing seed statement %q: %w", statement, err)
		}
	}
	return transaction.Commit()
}
