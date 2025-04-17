package types

import "time"

type Session struct {
	Id           string    `db:"id"`
	IpAddress    string    `db:"ip_address"`
	RefreshToken string    `db:"refresh_token"`
	IsRevoked    bool      `db:"is_revoked"`
	ExpiresAt    time.Time `db:"expires_at"`
}
