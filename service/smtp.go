package service

import "net/smtp"

type SmtpProviderInterface interface {
	SendMail(message string) error
}

type SmtpProvider struct {
	from     string
	to       string
	smtpHost string
	smtpPort string
	auth     smtp.Auth
}

func NewSmtpProvider(from, to, smtpHost, smtpPort, password string) *SmtpProvider {
	auth := smtp.PlainAuth("", from, password, smtpHost)
	return &SmtpProvider{
		from:     from,
		to:       to,
		smtpHost: smtpHost,
		smtpPort: smtpPort,
		auth:     auth,
	}
}

func (provider *SmtpProvider) SendMail(body string) error {
	message := []byte("Subject: Ip address mismatch" + "\r\n" + "\r\n" + body)

	err := smtp.SendMail(provider.smtpHost+":"+provider.smtpPort, provider.auth, provider.from, []string{provider.to}, message)
	if err != nil {
		return err
	}
	return nil
}
