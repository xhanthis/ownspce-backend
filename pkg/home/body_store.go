package home

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// MaxBodyDaysPerRead caps one body history read.
const MaxBodyDaysPerRead = 400

// MaxBodyDaysPerWrite caps the days one sync may send.
const MaxBodyDaysPerWrite = 31

// BodyProfile is what the balance maths needs about one member and what they are aiming for. Nil means unset.
// GoalBy is the day (yyyy-mm-dd) the goal weight should be reached by.
type BodyProfile struct {
	HeightCm    *int      `json:"heightCm"`
	BirthYear   *int      `json:"birthYear"`
	Sex         *string   `json:"sex"`
	GoalWeightG *int      `json:"goalWeightG"`
	GoalFatX10  *int      `json:"goalFatX10"`
	WeeklyG     int       `json:"weeklyG"`
	ProteinG    *int      `json:"proteinG"`
	GoalBy      *string   `json:"goalBy"`
	HealthSync  bool      `json:"healthSync"`
	UpdatedAt   time.Time `json:"updatedAt"`
}

// Workout is one exercise session as the phone's health store reported it.
type Workout struct {
	Type      string `json:"type"`
	StartedAt string `json:"startedAt"`
	Minutes   int    `json:"minutes"`
	Kcal      int    `json:"kcal"`
}

// BodyDay is one member's body and activity figures for one day. Weight and fat are nil until something sets them.
type BodyDay struct {
	Day          string    `json:"day"`
	WeightG      *int      `json:"weightG"`
	FatX10       *int      `json:"fatX10"`
	WeightSource string    `json:"weightSource"`
	ActiveKcal   int       `json:"activeKcal"`
	BasalKcal    *int      `json:"basalKcal"`
	ExerciseMin  int       `json:"exerciseMin"`
	Steps        int       `json:"steps"`
	SleepMin     *int      `json:"sleepMin"`
	SleepSource  string    `json:"sleepSource"`
	Workouts     []Workout `json:"workouts"`
	UpdatedAt    time.Time `json:"updatedAt"`
}

// BodyDayPatch carries the fields one write wants to set; nil leaves the stored value alone.
type BodyDayPatch struct {
	Day         string
	WeightG     *int
	FatX10      *int
	ActiveKcal  *int
	BasalKcal   *int
	ExerciseMin *int
	Steps       *int
	SleepMin    *int
	Workouts    *[]Workout
}

func scanBodyDay(row pgx.CollectableRow) (BodyDay, error) {
	var day BodyDay
	var source, sleepSource *string
	var workouts []byte
	if err := row.Scan(&day.Day, &day.WeightG, &day.FatX10, &source, &day.ActiveKcal, &day.BasalKcal, &day.ExerciseMin, &day.Steps, &workouts, &day.SleepMin, &sleepSource, &day.UpdatedAt); err != nil {
		return BodyDay{}, err
	}
	if source != nil {
		day.WeightSource = *source
	}
	if sleepSource != nil {
		day.SleepSource = *sleepSource
	}
	day.Workouts = []Workout{}
	if err := json.Unmarshal(workouts, &day.Workouts); err != nil {
		return BodyDay{}, fmt.Errorf("decode workouts: %w", err)
	}
	return day, nil
}

// BodyProfile reads one member's profile, or the defaults when none was saved yet.
func (s *Store) BodyProfile(ctx context.Context, userID uuid.UUID) (BodyProfile, error) {
	profile := BodyProfile{WeeklyG: 500}
	err := s.pool.QueryRow(ctx, "SELECT height_cm, birth_year, sex, goal_weight_g, goal_fat_x10, weekly_g, protein_g, to_char(goal_by, 'YYYY-MM-DD'), health_sync, updated_at FROM home_body_profiles WHERE user_id = $1", userID).Scan(&profile.HeightCm, &profile.BirthYear, &profile.Sex, &profile.GoalWeightG, &profile.GoalFatX10, &profile.WeeklyG, &profile.ProteinG, &profile.GoalBy, &profile.HealthSync, &profile.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return profile, nil
	}
	if err != nil {
		return BodyProfile{}, fmt.Errorf("read body profile: %w", err)
	}
	return profile, nil
}

// SaveBodyProfile writes the whole profile for one member (validated by the caller).
func (s *Store) SaveBodyProfile(ctx context.Context, userID uuid.UUID, profile BodyProfile) (BodyProfile, error) {
	if _, err := s.pool.Exec(ctx, "INSERT INTO home_body_profiles (user_id, height_cm, birth_year, sex, goal_weight_g, goal_fat_x10, weekly_g, health_sync, protein_g, goal_by) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10::date) ON CONFLICT (user_id) DO UPDATE SET height_cm = EXCLUDED.height_cm, birth_year = EXCLUDED.birth_year, sex = EXCLUDED.sex, goal_weight_g = EXCLUDED.goal_weight_g, goal_fat_x10 = EXCLUDED.goal_fat_x10, weekly_g = EXCLUDED.weekly_g, health_sync = EXCLUDED.health_sync, protein_g = EXCLUDED.protein_g, goal_by = EXCLUDED.goal_by, updated_at = now()", userID, profile.HeightCm, profile.BirthYear, profile.Sex, profile.GoalWeightG, profile.GoalFatX10, profile.WeeklyG, profile.HealthSync, profile.ProteinG, profile.GoalBy); err != nil {
		return BodyProfile{}, fmt.Errorf("save body profile: %w", err)
	}
	return s.BodyProfile(ctx, userID)
}

// BodyDays lists one member's days between two dates, newest first.
// Args: ctx, userID, from, to (yyyy-mm-dd, validated by the caller)
func (s *Store) BodyDays(ctx context.Context, userID uuid.UUID, from, to string) ([]BodyDay, error) {
	rows, err := s.pool.Query(ctx, "SELECT to_char(day, 'YYYY-MM-DD'), weight_g, fat_x10, weight_source, active_kcal, basal_kcal, exercise_min, steps, workouts, sleep_min, sleep_source, updated_at FROM home_body_days WHERE user_id = $1 AND day BETWEEN $2::date AND $3::date ORDER BY day DESC LIMIT $4", userID, from, to, MaxBodyDaysPerRead)
	if err != nil {
		return nil, fmt.Errorf("list body days: %w", err)
	}
	days, err := pgx.CollectRows(rows, scanBodyDay)
	if err != nil {
		return nil, fmt.Errorf("scan body days: %w", err)
	}
	return days, nil
}

// LatestWeight finds the member's most recent weighed day on or before a date, so a day with no reading still has
// a weight to compute with.
// Returns: ErrNotFound when the member has never been weighed
func (s *Store) LatestWeight(ctx context.Context, userID uuid.UUID, onOrBefore string) (BodyDay, error) {
	rows, err := s.pool.Query(ctx, "SELECT to_char(day, 'YYYY-MM-DD'), weight_g, fat_x10, weight_source, active_kcal, basal_kcal, exercise_min, steps, workouts, sleep_min, sleep_source, updated_at FROM home_body_days WHERE user_id = $1 AND day <= $2::date AND weight_g IS NOT NULL ORDER BY day DESC LIMIT 1", userID, onOrBefore)
	if err != nil {
		return BodyDay{}, fmt.Errorf("read latest weight: %w", err)
	}
	day, err := pgx.CollectOneRow(rows, scanBodyDay)
	if errors.Is(err, pgx.ErrNoRows) {
		return BodyDay{}, ErrNotFound
	}
	if err != nil {
		return BodyDay{}, fmt.Errorf("scan latest weight: %w", err)
	}
	return day, nil
}

// SaveBodyDays merges a batch of day patches for one member in one transaction. Nil fields keep their stored value.
// A weight typed by hand (source manual) is never overwritten by a health sync; a manual write always wins.
// Args: ctx, userID, patches (validated by the caller, at most MaxBodyDaysPerWrite), source ("health" or "manual")
// Returns: how many days were written
func (s *Store) SaveBodyDays(ctx context.Context, userID uuid.UUID, patches []BodyDayPatch, source string) (int, error) {
	err := pgx.BeginFunc(ctx, s.pool, func(tx pgx.Tx) error {
		batch := &pgx.Batch{}
		for _, patch := range patches {
			var workouts *string
			if patch.Workouts != nil {
				raw, err := json.Marshal(*patch.Workouts)
				if err != nil {
					return fmt.Errorf("encode workouts: %w", err)
				}
				encoded := string(raw)
				workouts = &encoded
			}
			batch.Queue("INSERT INTO home_body_days (user_id, day, weight_g, fat_x10, weight_source, active_kcal, basal_kcal, exercise_min, steps, workouts, sleep_min, sleep_source) VALUES ($1, $2::date, $3, $4, CASE WHEN $3::integer IS NULL THEN NULL ELSE $5 END, coalesce($6, 0), $7, coalesce($8, 0), coalesce($9, 0), coalesce($10::jsonb, '[]'::jsonb), $11, CASE WHEN $11::integer IS NULL THEN NULL ELSE $5 END) ON CONFLICT (user_id, day) DO UPDATE SET weight_g = CASE WHEN EXCLUDED.weight_g IS NULL OR (home_body_days.weight_source = 'manual' AND $5 = 'health') THEN home_body_days.weight_g ELSE EXCLUDED.weight_g END, fat_x10 = CASE WHEN EXCLUDED.fat_x10 IS NULL OR (home_body_days.weight_source = 'manual' AND $5 = 'health') THEN home_body_days.fat_x10 ELSE EXCLUDED.fat_x10 END, weight_source = CASE WHEN EXCLUDED.weight_g IS NULL OR (home_body_days.weight_source = 'manual' AND $5 = 'health') THEN home_body_days.weight_source ELSE $5 END, active_kcal = coalesce($6, home_body_days.active_kcal), basal_kcal = coalesce($7, home_body_days.basal_kcal), exercise_min = coalesce($8, home_body_days.exercise_min), steps = coalesce($9, home_body_days.steps), workouts = coalesce($10::jsonb, home_body_days.workouts), sleep_min = CASE WHEN EXCLUDED.sleep_min IS NULL OR (home_body_days.sleep_source = 'manual' AND $5 = 'health') THEN home_body_days.sleep_min ELSE EXCLUDED.sleep_min END, sleep_source = CASE WHEN EXCLUDED.sleep_min IS NULL OR (home_body_days.sleep_source = 'manual' AND $5 = 'health') THEN home_body_days.sleep_source ELSE $5 END, updated_at = now()", userID, patch.Day, patch.WeightG, patch.FatX10, source, patch.ActiveKcal, patch.BasalKcal, patch.ExerciseMin, patch.Steps, workouts, patch.SleepMin)
		}
		if err := tx.SendBatch(ctx, batch).Close(); err != nil {
			return fmt.Errorf("save body days: %w", err)
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	return len(patches), nil
}
