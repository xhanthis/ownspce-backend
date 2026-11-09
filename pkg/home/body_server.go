package home

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	maxBodyReadDays = 90
	maxWorkoutsADay = 30
	maxWorkoutType  = 40
	maxActiveKcal   = 20000
	maxBasalKcal    = 10000
	maxWorkoutKcal  = 10000
	maxExerciseMin  = 1440
	maxSleepMin     = 1440
	minProteinG     = 20
	maxProteinG     = 400
	maxSteps        = 200000
	minWeightG      = 20000
	maxWeightG      = 400000
	minFatX10       = 10
	maxFatX10       = 700
)

var sexes = set("male", "female")
var bodySources = set("health", "manual")

// getBody returns the member's own profile and days between two dates (at most 90 days apart), plus the latest
// weighed day on or before `to` so a day without a reading still has a weight to work with.
func (s *Server) getBody(w http.ResponseWriter, r *http.Request) {
	from, to := r.URL.Query().Get("from"), r.URL.Query().Get("to")
	if !validDate(from) || !validDate(to) || from > to {
		writeError(w, r, badRequest("from and to must be yyyy-mm-dd dates, from not after to"))
		return
	}
	start, _ := time.Parse("2006-01-02", from)
	end, _ := time.Parse("2006-01-02", to)
	if end.Sub(start) > maxBodyReadDays*24*time.Hour {
		writeError(w, r, badRequest(fmt.Sprintf("at most %d days at a time", maxBodyReadDays)))
		return
	}
	user := actor(r).ID
	profile, err := s.store.BodyProfile(r.Context(), user)
	if err != nil {
		writeError(w, r, err)
		return
	}
	days, err := s.store.BodyDays(r.Context(), user, from, to)
	if err != nil {
		writeError(w, r, err)
		return
	}
	var latest *BodyDay
	weighed, err := s.store.LatestWeight(r.Context(), user, to)
	if err == nil {
		latest = &weighed
	} else if !errors.Is(err, ErrNotFound) {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"profile": profile, "days": days, "latestWeight": latest})
}

type bodyProfileBody struct {
	HeightCm    *int    `json:"heightCm"`
	BirthYear   *int    `json:"birthYear"`
	Sex         *string `json:"sex"`
	GoalWeightG *int    `json:"goalWeightG"`
	GoalFatX10  *int    `json:"goalFatX10"`
	WeeklyG     int     `json:"weeklyG"`
	ProteinG    *int    `json:"proteinG"`
	HealthSync  bool    `json:"healthSync"`
}

func between(value *int, min, max int) bool {
	return value == nil || (*value >= min && *value <= max)
}

// putBodyProfile replaces the member's own profile. Missing optional fields clear the stored value.
func (s *Server) putBodyProfile(w http.ResponseWriter, r *http.Request) {
	var body bodyProfileBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	thisYear := time.Now().Year()
	switch {
	case !between(body.HeightCm, 100, 250):
		writeError(w, r, badRequest("height must be 100 to 250 cm"))
		return
	case !between(body.BirthYear, 1920, thisYear-10):
		writeError(w, r, badRequest(fmt.Sprintf("birth year must be 1920 to %d", thisYear-10)))
		return
	case !oneOfOrNil(body.Sex, sexes):
		writeError(w, r, badRequest("sex must be male or female"))
		return
	case !between(body.GoalWeightG, minWeightG, maxWeightG):
		writeError(w, r, badRequest("goal weight must be 20 to 400 kg"))
		return
	case !between(body.GoalFatX10, minFatX10, maxFatX10):
		writeError(w, r, badRequest("goal body fat must be 1 to 70 percent"))
		return
	case body.WeeklyG < 100 || body.WeeklyG > 1000:
		writeError(w, r, badRequest("pace must be 100 to 1000 g a week"))
		return
	case !between(body.ProteinG, minProteinG, maxProteinG):
		writeError(w, r, badRequest(fmt.Sprintf("protein target must be %d to %d g a day", minProteinG, maxProteinG)))
		return
	}
	saved, err := s.store.SaveBodyProfile(r.Context(), actor(r).ID, BodyProfile{HeightCm: body.HeightCm, BirthYear: body.BirthYear, Sex: body.Sex, GoalWeightG: body.GoalWeightG, GoalFatX10: body.GoalFatX10, WeeklyG: body.WeeklyG, ProteinG: body.ProteinG, HealthSync: body.HealthSync})
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, saved)
}

type bodyDayBody struct {
	Day         string     `json:"day"`
	WeightG     *int       `json:"weightG"`
	FatX10      *int       `json:"fatX10"`
	ActiveKcal  *int       `json:"activeKcal"`
	BasalKcal   *int       `json:"basalKcal"`
	ExerciseMin *int       `json:"exerciseMin"`
	Steps       *int       `json:"steps"`
	SleepMin    *int       `json:"sleepMin"`
	Workouts    *[]Workout `json:"workouts"`
}

type bodyDaysBody struct {
	Source string        `json:"source"`
	Days   []bodyDayBody `json:"days"`
}

// putBodyDays merges up to 31 days of figures for the member's own record. Fields left out keep their value.
// Handles: a health sync never overwrites a weight typed by hand; workouts are trimmed and capped
func (s *Server) putBodyDays(w http.ResponseWriter, r *http.Request) {
	var body bodyDaysBody
	if err := decode(r, &body); err != nil {
		writeError(w, r, err)
		return
	}
	if !bodySources[body.Source] {
		writeError(w, r, badRequest("source must be health or manual"))
		return
	}
	if len(body.Days) == 0 || len(body.Days) > MaxBodyDaysPerWrite {
		writeError(w, r, badRequest(fmt.Sprintf("send 1 to %d days", MaxBodyDaysPerWrite)))
		return
	}
	patches := make([]BodyDayPatch, 0, len(body.Days))
	seen := map[string]bool{}
	for _, day := range body.Days {
		switch {
		case !validDate(day.Day):
			writeError(w, r, badRequest(fmt.Sprintf("day %q is not a yyyy-mm-dd date", day.Day)))
			return
		case seen[day.Day]:
			writeError(w, r, badRequest(day.Day+" is listed twice"))
			return
		case !between(day.WeightG, minWeightG, maxWeightG):
			writeError(w, r, badRequest(day.Day+": weight must be 20 to 400 kg"))
			return
		case !between(day.FatX10, minFatX10, maxFatX10):
			writeError(w, r, badRequest(day.Day+": body fat must be 1 to 70 percent"))
			return
		case !between(day.ActiveKcal, 0, maxActiveKcal) || !between(day.BasalKcal, 0, maxBasalKcal):
			writeError(w, r, badRequest(day.Day+": calories out of range"))
			return
		case !between(day.ExerciseMin, 0, maxExerciseMin) || !between(day.Steps, 0, maxSteps):
			writeError(w, r, badRequest(day.Day+": minutes or steps out of range"))
			return
		case !between(day.SleepMin, 0, maxSleepMin):
			writeError(w, r, badRequest(day.Day+": sleep must be 0 to 1440 minutes"))
			return
		case day.FatX10 != nil && day.WeightG == nil:
			writeError(w, r, badRequest(day.Day+": body fat needs a weight"))
			return
		}
		seen[day.Day] = true
		patch := BodyDayPatch{Day: day.Day, WeightG: day.WeightG, FatX10: day.FatX10, ActiveKcal: day.ActiveKcal, BasalKcal: day.BasalKcal, ExerciseMin: day.ExerciseMin, Steps: day.Steps, SleepMin: day.SleepMin}
		if day.Workouts != nil {
			if len(*day.Workouts) > maxWorkoutsADay {
				writeError(w, r, badRequest(fmt.Sprintf("%s: at most %d workouts", day.Day, maxWorkoutsADay)))
				return
			}
			workouts := make([]Workout, 0, len(*day.Workouts))
			for _, raw := range *day.Workouts {
				workout := Workout{Type: strings.TrimSpace(raw.Type), StartedAt: strings.TrimSpace(raw.StartedAt), Minutes: raw.Minutes, Kcal: raw.Kcal}
				if !textBetween(workout.Type, 1, maxWorkoutType) || !textBetween(workout.StartedAt, 0, 40) || workout.Minutes < 0 || workout.Minutes > maxExerciseMin || workout.Kcal < 0 || workout.Kcal > maxWorkoutKcal {
					writeError(w, r, badRequest(day.Day+": a workout is out of range"))
					return
				}
				workouts = append(workouts, workout)
			}
			patch.Workouts = &workouts
		}
		patches = append(patches, patch)
	}
	saved, err := s.store.SaveBodyDays(r.Context(), actor(r).ID, patches, body.Source)
	if err != nil {
		writeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"saved": saved})
}
