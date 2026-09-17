package mailer

import (
	"fmt"
	"net/smtp"

	"github.com/koray-killi/AuthCore/internal/config"
)

// smtpMailer implements Mailer using net/smtp. Works with MailHog in development.
type smtpMailer struct {
	cfg config.SMTPConfig
}

// NewSMTPMailer creates a new SMTP-based mailer.
func NewSMTPMailer(cfg config.SMTPConfig) Mailer {
	return &smtpMailer{cfg: cfg}
}

func (m *smtpMailer) SendVerificationEmail(to, code string) error {
	subject := "Verify your email address"
	body := fmt.Sprintf(
		"Welcome to AuthCore!\n\nYour email verification code is: %s\n\nThis code expires in 10 minutes.\n\nIf you did not create an account, you can safely ignore this email.",
		code,
	)
	return m.send(to, subject, body)
}

func (m *smtpMailer) SendPasswordResetEmail(to, code string) error {
	subject := "Reset your password"
	body := fmt.Sprintf(
		"You requested a password reset.\n\nYour password reset code is: %s\n\nThis code expires in 10 minutes.\n\nIf you did not request this, you can safely ignore this email.",
		code,
	)
	return m.send(to, subject, body)
}

func (m *smtpMailer) send(to, subject, body string) error {
	addr := fmt.Sprintf("%s:%d", m.cfg.Host, m.cfg.Port)

	msg := fmt.Sprintf(
		"From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=\"utf-8\"\r\n\r\n%s",
		m.cfg.From, to, subject, body,
	)

	var auth smtp.Auth
	if m.cfg.Username != "" {
		auth = smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
	}

	return smtp.SendMail(addr, auth, m.cfg.From, []string{to}, []byte(msg))
}
