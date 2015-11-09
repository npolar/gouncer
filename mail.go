package gouncer

import (
	"errors"
	"fmt"
	"net/smtp"
	"net/url"
	"regexp"
	"strings"
)

const (
	linkPattern = "{{link}}"
	codePattern = "{{code}}"
)

type Mail struct {
	Recipient   string
	LinkID      string
	*Core       // Core auth server configuration
	*Backend    // Backend configuration
	*MailConfig // Mail Configuration
}

type MailConfig struct {
	Sender           string   // Email address the messages are sent from
	LinkTimeout      int32    // Time confirmation and cancellation links stay active
	ConfirmSubject   string   // Confirmation mail subject field
	ConfirmMessage   string   // Confirmation mail content body
	CancelSubject    string   // Cancellation mail subject field
	CancelMessage    string   // Cancellation mail content body
	OneTimeSubject   string   // OneTime login mail subject
	OneTimeMessage   string   // OneTime login mail content body
	WhitelistDomains []string // Whitelisted domains that are allowed to handle confirmation and cancellation messages
}

func NewMailClient(recipient string, linkID string) *Mail {
	return &Mail{
		LinkID:    linkID,
		Recipient: recipient,
	}
}

func (m *Mail) Confirmation(link string) error {
	if m.allowedDomain(link) {

		var message string

		rxp := regexp.MustCompile(linkPattern)
		rxp2 := regexp.MustCompile(codePattern)

		if m.ConfirmMessage != "" {
			message = "Subject:" + m.ConfirmSubject + "\r\n\r\n"
			message += rxp2.ReplaceAllString(rxp.ReplaceAllString(m.ConfirmMessage, link), m.LinkID)
		} else {
			message = "Subject:Account Registration\r\n"
			message += "Thank you for registering.\r\n"
			message += "To complete your registration please click the following link: "
			message += link + "/" + m.LinkID + "\r\n"
			message += "Please delete this message if you did not try to register an account with us."
		}

		return m.SendMail(message)
	} else {
		return errors.New("Confirmation link does not appear on the whitelist")
	}
}

// @TODO add link injection for cancellation messages
func (m *Mail) Cancellation() error {
	var message string

	rxp := regexp.MustCompile(linkPattern)

	if m.ConfirmMessage != "" {
		message = "Subject:" + m.CancelSubject + "\r\n\r\n"
		rxp.ReplaceAllString(m.ConfirmMessage, m.LinkID)
	} else {
		message = "Subject:Account Cancellation\r\n"
		message += "Click the following link to complete the cancellation process: "
		message += m.LinkID + "\r\n"
		message += "Please delete this message if you do not wish to cancel your account."
	}

	return m.SendMail(message)
}

func (m *Mail) OneTimePassword(pwd string) error {
	var message string
	rxp := regexp.MustCompile(linkPattern)

	if m.ConfirmMessage != "" {
		message = "Subject:" + m.OneTimeSubject + "\n\n"
		message += rxp.ReplaceAllString(m.OneTimeMessage, pwd)
	} else {
		message = "Subject:One time password\n\n"
		message += "You can use your email and the follwing password to login: " + pwd
	}

	return m.SendMail(message)
}

// Generate an SMTP request with the provided message
func (m *Mail) SendMail(message string) error {
	// Connect to the remote SMTP server specified through the commandline.
	c, err := smtp.Dial(m.Smtp)
	if err != nil {
		return err
	}

	// Set the sender
	if err := c.Mail(m.Sender); err != nil {
		return err
	}

	// Set the recipient
	if err := c.Rcpt(m.Recipient); err != nil {
		return err
	}

	// Send the email body.
	wc, err := c.Data()
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(wc, message)
	if err != nil {
		return err
	}
	err = wc.Close()
	if err != nil {
		return err
	}

	// Send the QUIT command and close the connection.
	err = c.Quit()
	if err != nil {
		return err
	}

	return nil
}

func (m *Mail) allowedDomain(link string) bool {
	if l, err := url.Parse(link); err == nil {
		for _, white := range m.WhitelistDomains {
			if a, err := url.Parse(white); err == nil {
				if m.linksMatch(l, a) {
					return true
				}
			}
		}
	}

	return false
}

func (m *Mail) linksMatch(a *url.URL, b *url.URL) bool {
	return a.Scheme == b.Scheme && a.Host == b.Host && m.pathMatch(a.Path, b.Path)
}

func (m *Mail) pathMatch(a string, b string) bool {
	return a == b || m.WildcardPathMatch(b, a)
}

func (m *Mail) WildcardPathMatch(pathA string, pathB string) bool {
	segsA := strings.Split(pathA, "/")
	segsB := strings.Split(pathB, "/")

	match := true

	for i, seg := range segsA {
		if segsB[i] != seg && seg != "*" {
			match = false
		}
	}

	return match
}
