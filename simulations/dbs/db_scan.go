package dbs

import (
	"database/sql"
	"fmt"
	"log"
	"time"

	"github.com/KennyZ69/go-aptt/types"
)

func DB_Scan(mode, db_type string) ([]types.Vulnerability, error) {
	log.Printf("Starting the DB Scan in %s mode\n", mode)
	// TODO: I need to somehow copy the database the is given to be able to run the attacks if the specified mode is "attack"

	// Set up mock database to test the simulations
	// Later I should try to do something like the user provides the sql structure from a file or directory with files, I could scan it somehow or just copy it all, run it in the docker sandbox to have the same thing (provided it not like googles database or something) and do the tests then
	// probably would take a lot of fucking time but whatever, could optimize maybe somehow a bit

	connStr := "host=db password=testpassword user=test dbname=security_scan_db sslmode=disable"
	db, err := sql.Open(db_type, connStr)
	if err != nil {
		log.Fatalf("Failed to connect to the database: %v\n", err)
		return nil, fmt.Errorf("Error connecting to db for sandbox enviroment")
	}
	defer db.Close()
	// Check if the connection is valid
	if err = waitForDB(db); err != nil {
		log.Fatalf("Failed to ping the database: %v", err)
		return nil, err
	}

	return nil, nil
}

func waitForDB(db *sql.DB) error {
	retryCount := 10
	for i := 0; i < retryCount; i++ {
		err := db.Ping()
		if err == nil {
			return nil
		}
		log.Printf("Database not ready, retrying... (%d/%d)\n", i+1, retryCount)
		time.Sleep(3 * time.Second)
	}
	return fmt.Errorf("failed to connect to the database after %d retries", retryCount)
}
