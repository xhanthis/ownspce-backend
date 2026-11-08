package home

import (
	"context"
	"os"
	"sync"
	"testing"
)

// TestColdStartSkipsTheSchemaOnceTheDatabaseMatchesTheBuild proves the boot path: a database that already carries
// this build's fingerprint is left alone, a stale fingerprint brings the schema and both seeds back, and the
// seeded dishes are there either way.
func TestColdStartSkipsTheSchemaOnceTheDatabaseMatchesTheBuild(t *testing.T) {
	first := testStore(t)
	ctx := context.Background()
	url := os.Getenv("HOME_TEST_DATABASE_URL")

	second, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("second open: %v", err)
	}
	t.Cleanup(second.Close)
	if second.Applied {
		t.Fatal("the database already matched this build, so the second open should have skipped the schema")
	}

	if _, err := first.pool.Exec(ctx, "UPDATE home_meta SET value = 'stale' WHERE key = 'schema'"); err != nil {
		t.Fatalf("age the fingerprint: %v", err)
	}
	third, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("third open: %v", err)
	}
	t.Cleanup(third.Close)
	if !third.Applied {
		t.Fatal("a stale fingerprint should make open run the schema again")
	}
	var stored string
	if err := third.pool.QueryRow(ctx, "SELECT value FROM home_meta WHERE key = 'schema'").Scan(&stored); err != nil || stored != schemaFingerprint() {
		t.Fatalf("the fingerprint should be this build's after a run: %q %v", stored, err)
	}

	var dishes, categories int
	if err := third.pool.QueryRow(ctx, "SELECT count(*) FROM home_dishes WHERE created_by IS NULL").Scan(&dishes); err != nil || dishes == 0 {
		t.Fatalf("seeded dishes should be present: %d %v", dishes, err)
	}
	if err := third.pool.QueryRow(ctx, "SELECT count(*) FROM home_categories").Scan(&categories); err != nil || categories == 0 {
		t.Fatalf("seeded categories should be present: %d %v", categories, err)
	}

	fourth, err := Open(ctx, url)
	if err != nil {
		t.Fatalf("fourth open: %v", err)
	}
	t.Cleanup(fourth.Close)
	if fourth.Applied {
		t.Fatal("once recorded, the next open skips again")
	}

	if _, err := first.pool.Exec(ctx, "UPDATE home_meta SET value = 'stale' WHERE key = 'schema'"); err != nil {
		t.Fatalf("age the fingerprint again: %v", err)
	}
	var wg sync.WaitGroup
	applied := make([]bool, 4)
	for index := range applied {
		wg.Add(1)
		go func() {
			defer wg.Done()
			store, err := Open(ctx, url)
			if err != nil {
				t.Errorf("concurrent open: %v", err)
				return
			}
			defer store.Close()
			applied[index] = store.Applied
		}()
	}
	wg.Wait()
	ran := 0
	for _, did := range applied {
		if did {
			ran++
		}
	}
	if ran != 1 {
		t.Fatalf("four cold instances at once should run the schema exactly once, got %d: %v", ran, applied)
	}
}
