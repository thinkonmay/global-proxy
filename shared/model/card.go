package model

// CardRow is a saved card persisted in billing.card.
type CardRow struct {
	UserID      int64
	Provider    string
	CustomerRef string
	PMRef       string
	Brand       string
	Last4       string
	ExpMonth    int
	ExpYear     int
}
