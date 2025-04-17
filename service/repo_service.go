package service

import (
	"PartAuthService/db"
	"PartAuthService/types"
)

type RepoServiceInterface interface {
	CreateSession(session *types.Session) error
	GetSessionById(id string) (*types.Session, error)
	UpdateSession(session *types.Session) error
}

type RepoService struct {
	sessionRepo db.SessionRepo
}

func NewRepoService(database *db.Database) *RepoService {
	return &RepoService{
		sessionRepo: *db.NewSessionRepo(database),
	}
}

func (r *RepoService) CreateSession(session *types.Session) error {
	return r.sessionRepo.CreateSession(session)
}

func (r *RepoService) GetSessionById(id string) (*types.Session, error) {
	return r.sessionRepo.GetSessionById(id)
}

func (r *RepoService) UpdateSession(session *types.Session) error {
	return r.sessionRepo.UpdateSession(session)
}
