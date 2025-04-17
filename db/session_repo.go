package db

import (
	"PartAuthService/types"
)

type SessionRepo struct {
	db *Database
}

func NewSessionRepo(db *Database) *SessionRepo {
	return &SessionRepo{db: db}
}

func (r *SessionRepo) CreateSession(session *types.Session) error {
	query := `INSERT INTO sessions (id, ip_address, refresh_token, expires_at) VALUES ($1, $2, $3, $4)`
	_, err := r.db.GetDB().Exec(query, session.Id, session.IpAddress, session.RefreshToken, session.ExpiresAt)
	return err
}

func (r *SessionRepo) GetSessionById(id string) (*types.Session, error) {
	query := `SELECT id, ip_address, refresh_token, is_revoked, expires_at FROM sessions WHERE id = $1`
	row := r.db.GetDB().QueryRow(query, id)
	session := &types.Session{}
	err := row.Scan(&session.Id, &session.IpAddress, &session.RefreshToken, &session.IsRevoked, &session.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return session, nil
}

func (r *SessionRepo) UpdateSession(session *types.Session) error {
	query := `UPDATE sessions SET ip_address = $1, refresh_token = $2, is_revoked = $3, expires_at = $4 WHERE id = $5`
	_, err := r.db.GetDB().Exec(query, session.IpAddress, session.RefreshToken, session.IsRevoked, session.ExpiresAt, session.Id)
	return err
}
