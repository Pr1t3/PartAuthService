package main

import (
	"PartAuthService/db"
	"PartAuthService/handler"
	"PartAuthService/service"
	"fmt"
	"log"
	"os"

	"github.com/joho/godotenv"
)

func main() {
	err := godotenv.Load()
	if err != nil {
		log.Printf("Error loading .env file: %v", err)
	}
	secretKey := os.Getenv("SECRET_KEY")
	user := os.Getenv("POSTGRES_USER")
	password := os.Getenv("POSTGRES_PASSWORD")
	port := os.Getenv("POSTGRES_PORT")
	dbName := os.Getenv("POSTGRES_DB")
	smtpFrom := os.Getenv("SMTP_FROM")
	smtpTo := os.Getenv("SMTP_TO")
	smtpHost := os.Getenv("SMTP_HOST")
	smtpPort := os.Getenv("SMTP_PORT")
	smtpPassword := os.Getenv("SMTP_PASSWORD")
	servicePort := os.Getenv("PORT")
	hostName := os.Getenv("HOST_NAME")

	database, err := db.NewDatabase(fmt.Sprintf("postgresql://%s:%s@%s:%s/%s?sslmode=disable", user, password, hostName, port, dbName))
	if err != nil {
		panic(err)
	}
	defer database.Close()

	jwtCreator := service.NewJwtCreator(secretKey)
	repoService := service.NewRepoService(database)
	smtpProvider := service.NewSmtpProvider(smtpFrom, smtpTo, smtpHost, smtpPort, smtpPassword)
	h := handler.NewHandler(jwtCreator, repoService, smtpProvider)
	handler.RegisterRoutes(h)
	handler.Start(servicePort)
}
