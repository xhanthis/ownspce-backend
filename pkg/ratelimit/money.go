package ratelimit

import "time"

// Money limits. The ledger is chattier than the encrypted surfaces — a session
// refetches the feed, the summary and the budgets on every range change — so
// reads are generous. Writes are bounded by what a person can physically enter,
// and invites are the one route that sends mail on someone else's behalf, so it
// is the tightest of the three.
var (
	MoneyRead   = Rule{Name: "money_read", Max: 240, Window: time.Minute}
	MoneyWrite  = Rule{Name: "money_write", Max: 120, Window: time.Minute}
	MoneyInvite = Rule{Name: "money_invite", Max: 20, Window: time.Hour}
)
