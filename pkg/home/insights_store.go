package home

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// eatingOutPattern matches category names that mean the food came from outside the kitchen. Shared with the app,
// which uses the same words to pick the spend score's eating-out slice.
const eatingOutPattern = `%(eat|dining|restaurant|food|swiggy|zomato|takeaway|take-away|order)%`

// orderedInWindow is how far apart a meal tick and an eating-out spend may be and still count as the same meal.
const orderedInWindow = time.Hour

// MarkOrderedIn sets the ordered-in flag on a meal that was just ticked. With an explicit answer it writes that;
// without one, it turns the flag on when an eating-out spend was logged for the meal's day within the last hour.
// Handles: a flag already on is never turned off by the automatic rule
func (s *Store) MarkOrderedIn(ctx context.Context, mealID uuid.UUID, explicit *bool) error {
	if explicit != nil {
		if _, err := s.pool.Exec(ctx, "UPDATE home_meals SET ordered_in = $2, updated_at = now() WHERE id = $1", mealID, *explicit); err != nil {
			return fmt.Errorf("mark ordered in: %w", err)
		}
		return nil
	}
	_, err := s.pool.Exec(ctx, "UPDATE home_meals m SET ordered_in = true, updated_at = now() WHERE m.id = $1 AND NOT m.ordered_in AND EXISTS (SELECT 1 FROM home_entries e JOIN home_categories c ON c.id = e.category_id WHERE e.type = 'expense' AND e.occurred_on = m.day AND e.created_at >= now() - $2::interval AND lower(c.name) SIMILAR TO $3)", mealID, orderedInWindow, eatingOutPattern)
	if err != nil {
		return fmt.Errorf("mark ordered in from spend: %w", err)
	}
	return nil
}

// MarkOrderedInAroundEntry flags the meals the actor ticked in the last hour on the entry's day as ordered in, when
// the entry sits in an eating-out category. One statement; nothing happens for any other category.
func (s *Store) MarkOrderedInAroundEntry(ctx context.Context, entry Entry, actor uuid.UUID) error {
	_, err := s.pool.Exec(ctx, "UPDATE home_meals m SET ordered_in = true, updated_at = now() FROM home_meal_ticks t WHERE t.meal_id = m.id AND t.user_id = $1 AND m.day = $2::date AND NOT m.ordered_in AND t.ticked_at >= now() - $3::interval AND EXISTS (SELECT 1 FROM home_categories c WHERE c.id = $4 AND lower(c.name) SIMILAR TO $5)", actor, entry.OccurredOn, orderedInWindow, entry.CategoryID, eatingOutPattern)
	if err != nil {
		return fmt.Errorf("mark ordered in around entry: %w", err)
	}
	return nil
}

// InsightNote returns the note written earlier for exactly these figures, or ErrNotFound.
func (s *Store) InsightNote(ctx context.Context, userID uuid.UUID, figuresHash string) (string, error) {
	var note string
	err := s.pool.QueryRow(ctx, "SELECT note FROM home_insight_notes WHERE user_id = $1 AND figures_hash = $2", userID, figuresHash).Scan(&note)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read insight note: %w", err)
	}
	return note, nil
}

// LatestInsightNote returns the newest note this member has, whatever figures it was for, or ErrNotFound.
func (s *Store) LatestInsightNote(ctx context.Context, userID uuid.UUID) (string, error) {
	var note string
	err := s.pool.QueryRow(ctx, "SELECT note FROM home_insight_notes WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1", userID).Scan(&note)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	if err != nil {
		return "", fmt.Errorf("read latest insight note: %w", err)
	}
	return note, nil
}

// InsightNotesToday counts the notes written for this member since midnight UTC, for the daily model-call cap.
func (s *Store) InsightNotesToday(ctx context.Context, userID uuid.UUID) (int, error) {
	var count int
	if err := s.pool.QueryRow(ctx, "SELECT count(*) FROM home_insight_notes WHERE user_id = $1 AND created_at >= date_trunc('day', now())", userID).Scan(&count); err != nil {
		return 0, fmt.Errorf("count insight notes: %w", err)
	}
	return count, nil
}

// SaveInsightNote keeps a note for one set of figures. Writing the same figures twice keeps the newer note.
func (s *Store) SaveInsightNote(ctx context.Context, userID uuid.UUID, figuresHash, note string) error {
	if _, err := s.pool.Exec(ctx, "INSERT INTO home_insight_notes (user_id, figures_hash, note) VALUES ($1, $2, $3) ON CONFLICT (user_id, figures_hash) DO UPDATE SET note = EXCLUDED.note, created_at = now()", userID, figuresHash, note); err != nil {
		return fmt.Errorf("save insight note: %w", err)
	}
	return nil
}
