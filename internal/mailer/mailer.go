// Package mailer defines the email sending interface and implementations.
package mailer

// Mailer is the interface for sending emails. The SMTP implementation is the default;
// a mock implementation can be swapped in for testing.
type Mailer interface {
	// SendVerificationEmail sends an email verification OTP code to the given address.
	SendVerificationEmail(to, code string) error
	// SendPasswordResetEmail sends a password reset OTP code to the given address.
	SendPasswordResetEmail(to, code string) error
}
