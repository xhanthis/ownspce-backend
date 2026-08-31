// Command seed-money-demo creates a throwaway household with realistic entries
// and prints a browser session for it, so the Kosh web client can be driven
// against the real API without a Google sign-in.
//
// It exists for local verification and demos. It never runs in production: it
// requires DATABASE_URL and JWT_PRIVATE_KEY from the environment, mints users
// under an @ownspce.demo address, and prints everything it created so the rows
// can be removed again with cmd/seed-money-demo -clean.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/ownspce/backend/pkg/auth"
	"github.com/ownspce/backend/pkg/config"
	"github.com/ownspce/backend/pkg/dotenv"
	"github.com/ownspce/backend/pkg/store"
)

// demoDomain marks every account this command creates, so cleanup can find them
// without touching a real user.
const demoDomain = "@ownspce.demo"

type member struct {
	name  string
	email string
	id    uuid.UUID
}

// entry is one seeded ledger row, offset in days back from today.
type entry struct {
	daysAgo  int
	kind     string
	category string
	minor    int64
	note     string
	payer    int
	shared   bool
}

var entries = []entry{
	{0, "expense", "Groceries", 248000, "Weekly big shop", 1, true},
	{0, "expense", "Food", 64000, "Filter coffee and snacks", 0, false},
	{0, "expense", "Transport", 31000, "Auto to office", 0, false},
	{1, "expense", "Kids", 145000, "Cricket coaching kit", 1, true},
	{1, "expense", "Food", 189000, "Friday dinner out", 0, true},
	{1, "income", "Freelance", 2200000, "Design retainer", 1, false},
	{2, "expense", "Utilities", 320000, "BESCOM electricity", 0, true},
	{2, "expense", "Subscriptions", 64900, "Streaming bundle", 2, true},
	{3, "expense", "Groceries", 112000, "Milk, fruit, eggs", 2, true},
	{3, "expense", "Transport", 240000, "Petrol", 0, true},
	{4, "expense", "Shopping", 429000, "Kurta set for a wedding", 1, false},
	{4, "income", "Dividends", 640000, "Quarterly payout", 0, false},
	{5, "expense", "Healthcare", 180000, "Dentist", 1, true},
	{6, "expense", "Groceries", 296000, "Monthly staples", 1, true},
	{7, "expense", "Household", 900000, "Maid and cook", 0, true},
	{8, "expense", "Travel", 860000, "Train tickets", 0, true},
	{9, "expense", "Education", 1850000, "School fees", 1, true},
	{10, "expense", "Transport", 42000, "Metro top-up", 2, false},
	{11, "expense", "Subscriptions", 125000, "Broadband", 0, true},
	{12, "expense", "Groceries", 167000, "Vegetables", 1, true},
	{13, "expense", "Shopping", 340000, "Running shoes", 2, false},
	{14, "expense", "Food", 210000, "Anniversary dinner", 0, true},
	{15, "expense", "Utilities", 140000, "Water and gas", 0, true},
	{16, "expense", "Healthcare", 260000, "Pharmacy and tests", 1, true},
	{18, "expense", "Groceries", 224000, "Weekly big shop", 1, true},
	{20, "expense", "Household", 3840000, "Home loan EMI", 0, true},
	{21, "expense", "Rent", 5200000, "Flat rent", 0, true},
	{21, "income", "Salary", 18600000, "Monthly salary", 0, true},
	{21, "income", "Salary", 9800000, "Monthly salary", 1, true},
	{24, "expense", "Shopping", 279000, "Kitchen storage", 1, true},
	{26, "expense", "Travel", 320000, "Weekend drive fuel", 0, true},
}

var budgets = map[string]int64{
	"Groceries": 2400000, "Food": 1200000, "Transport": 900000, "Rent": 5200000,
	"Utilities": 800000, "Subscriptions": 350000, "Kids": 1000000, "Shopping": 1200000,
	"Healthcare": 600000,
}

type holding struct {
	name      string
	badge     string
	assetType string
	units     string
	avgMinor  int64
	nowMinor  int64
	bps       int
	sipMinor  int64
	color     string
	owner     int
}

var holdings = []holding{
	{"Nifty 50 Index Fund", "IDX", "mutual_fund", "2840", 16840, 21490, 62, 2500000, "#279AF4", 0},
	{"Parag Parikh Flexi Cap", "PPF", "mutual_fund", "1180", 5210, 7835, 41, 1500000, "#6E7BF1", 1},
	{"HDFC Bank", "HDB", "stocks", "240", 148200, 167100, -83, 0, "#EC7A58", 0},
	{"Infosys", "INFY", "stocks", "160", 139000, 154400, 124, 0, "#C56AF7", 0},
	{"Sovereign Gold Bond", "SGB", "gold", "90", 521000, 718000, 28, 0, "#F3BF56", 1},
	{"EPF and VPF", "EPF", "retirement", "1", 118000000, 134200000, 0, 2100000, "#5FAF9F", 0},
	{"SBI Fixed Deposit", "FD", "debt", "1", 40000000, 42860000, 0, 0, "#88997A", 1},
}

func main() {
	clean := flag.Bool("clean", false, "delete every demo user and everything cascading from them")
	allowRemote := flag.Bool("allow-remote", false, "permit running against a database that is not local; required for any non-localhost DSN")
	origin := flag.String("origin", "http://localhost:5003", "web origin the printed session is for")
	flag.Parse()

	dotenv.Load(".env")
	ctx := context.Background()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}
	// ENV alone is not a safe guard: it describes the local process, not the
	// database the DSN points at, so ENV=development with a production
	// DATABASE_URL would happily write demo households into real data. What
	// matters is which database this is actually connected to.
	if cfg.IsProduction() {
		log.Fatal("refusing to run with ENV=production")
	}
	if !isLocalDSN(cfg.DatabaseURL) && !*allowRemote {
		log.Fatal("DATABASE_URL does not point at localhost; re-run with -allow-remote if you really mean to touch a remote database")
	}

	st, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}
	defer st.Close()

	if *clean {
		tag, err := st.Pool().Exec(ctx, "DELETE FROM users WHERE email LIKE '%'||$1", demoDomain)
		if err != nil {
			log.Fatalf("clean: %v", err)
		}
		fmt.Printf("removed %d demo users and everything cascading from them\n", tag.RowsAffected())
		return
	}

	people := []member{
		{name: "Arjun", email: "arjun-" + uuid.NewString()[:8] + demoDomain},
		{name: "Priya", email: "priya-" + uuid.NewString()[:8] + demoDomain},
		{name: "Rohan", email: "rohan-" + uuid.NewString()[:8] + demoDomain},
	}
	for i := range people {
		user, _, err := st.UpsertUserByProvider(ctx, "google", "demo-"+uuid.NewString(), people[i].email, people[i].name, "")
		if err != nil {
			log.Fatalf("create %s: %v", people[i].name, err)
		}
		people[i].id = user.ID
	}

	spaceID, err := st.CreateMoneyHousehold(ctx, people[0].id)
	if err != nil {
		log.Fatalf("create household: %v", err)
	}
	for _, person := range people[1:] {
		if _, err := st.Pool().Exec(ctx, "INSERT INTO space_members (space_id, user_id, role) VALUES ($1, $2, 'editor')", spaceID, person.id); err != nil {
			log.Fatalf("add %s: %v", person.name, err)
		}
	}

	categories, err := st.ListMoneyCategories(ctx, spaceID, false)
	if err != nil {
		log.Fatalf("list categories: %v", err)
	}
	byName := make(map[string]uuid.UUID, len(categories))
	for _, category := range categories {
		byName[category.Name] = category.ID
	}

	today := time.Now().UTC().Truncate(24 * time.Hour)
	for _, row := range entries {
		categoryID, ok := byName[row.category]
		if !ok {
			log.Fatalf("seed references unknown category %q", row.category)
		}
		payer := people[row.payer].id
		if _, err := st.CreateMoneyTransaction(ctx, store.MoneyTransaction{
			SpaceID: spaceID, ClientID: uuid.New(), CategoryID: categoryID, Type: row.kind,
			AmountMinor: row.minor, Currency: "INR", OccurredOn: today.AddDate(0, 0, -row.daysAgo),
			Note: row.note, IsShared: row.shared, PaidBy: &payer, CreatedBy: &payer,
		}); err != nil {
			log.Fatalf("seed entry %q: %v", row.note, err)
		}
	}

	for name, limit := range budgets {
		if categoryID, ok := byName[name]; ok {
			if _, err := st.UpsertMoneyBudget(ctx, spaceID, categoryID, limit); err != nil {
				log.Fatalf("seed budget %s: %v", name, err)
			}
		}
	}

	for _, h := range holdings {
		owner := people[h.owner].id
		if _, err := st.CreateMoneyHolding(ctx, store.MoneyHolding{
			SpaceID: spaceID, OwnerID: &owner, Name: h.name, Badge: h.badge, AssetType: h.assetType,
			Units: h.units, AvgCostMinor: h.avgMinor, LastPriceMinor: h.nowMinor, DayChangeBps: h.bps,
			SIPMinor: h.sipMinor, Currency: "INR", Color: h.color,
		}); err != nil {
			log.Fatalf("seed holding %s: %v", h.name, err)
		}
	}

	for _, bill := range []struct {
		name     string
		emoji    string
		category string
		minor    int64
		day      int
	}{
		{"Rent", "🏠", "Rent", 5200000, 3},
		{"Home loan EMI", "🏦", "Household", 3840000, 5},
		{"Electricity", "💡", "Utilities", 320000, 9},
		{"School fees", "📚", "Education", 1850000, 10},
		{"Broadband and mobile", "🔄", "Subscriptions", 189900, 14},
	} {
		categoryID := byName[bill.category]
		if _, err := st.CreateMoneyBill(ctx, store.MoneyBill{
			SpaceID: spaceID, Name: bill.name, Emoji: bill.emoji, CategoryID: &categoryID,
			AmountMinor: bill.minor, DayOfMonth: bill.day, IsShared: true, PaidBy: &people[0].id,
		}); err != nil {
			log.Fatalf("seed bill %s: %v", bill.name, err)
		}
	}

	device, err := st.RegisterDevice(ctx, people[0].id, "Demo browser", "web", randomKey())
	if err != nil {
		log.Fatalf("register device: %v", err)
	}
	signer := auth.NewSigner(cfg.JWTPrivateKey, cfg.JWTPublicKey)
	accessToken, expiresAt, err := signer.Mint(people[0].id, device.ID)
	if err != nil {
		log.Fatalf("mint token: %v", err)
	}
	refresh, err := st.IssueRefreshToken(ctx, people[0].id, device.ID, "web", nil)
	if err != nil {
		log.Fatalf("issue refresh token: %v", err)
	}

	session := map[string]any{
		"accessToken":  accessToken,
		"refreshToken": refresh.Plaintext,
		"expiresAt":    expiresAt.UnixMilli(),
		"user": map[string]any{
			"id": people[0].id, "email": people[0].email, "name": people[0].name, "username": nil,
			"avatarUrl": nil, "plan": "free", "theme": "system", "font": "grotesk", "palette": "cream",
			"language": "en", "notifyEmail": true, "notifyPush": true, "streakCount": 0,
		},
	}
	encoded, err := json.Marshal(session)
	if err != nil {
		log.Fatalf("encode session: %v", err)
	}

	fmt.Printf("household  %s\n", spaceID)
	fmt.Printf("owner      %s (%s)\n", people[0].name, people[0].email)
	fmt.Printf("entries    %d, budgets %d, holdings %d\n", len(entries), len(budgets), len(holdings))
	fmt.Printf("expires    %s\n\n", expiresAt.Format(time.RFC3339))
	fmt.Printf("Paste into the console at %s to sign this browser in:\n\n", *origin)
	fmt.Printf("localStorage.setItem('ownspce.money.session.v1', %s); location.reload()\n", strconv.Quote(string(encoded)))
	fmt.Fprintln(os.Stderr, "\nremove it all again with: go run ./cmd/seed-money-demo -clean")
}

// isLocalDSN reports whether a connection string points at this machine.
// Args: dsn (a Postgres URL)
// Returns: true only for an unmistakably local host
// Handles: an unparseable DSN, treated as not local, so a malformed string
// fails closed rather than opening the door
func isLocalDSN(dsn string) bool {
	parsed, err := url.Parse(dsn)
	if err != nil {
		return false
	}
	host := parsed.Hostname()
	return host == "localhost" || host == "127.0.0.1" || host == "::1"
}

// randomKey returns 32 bytes standing in for a device public key.
func randomKey() []byte {
	key := make([]byte, 32)
	id := uuid.New()
	copy(key, id[:])
	id = uuid.New()
	copy(key[16:], id[:])
	return key
}
