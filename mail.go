package gouncer

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/smtp"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

const (
	linkPattern = "{{link}}"
	codePattern = "{{code}}"
	userPattern = "{{user}}"
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
			message += rxp.ReplaceAllString(m.ConfirmMessage, link)
			message = rxp2.ReplaceAllString(message, m.LinkID)
		} else {
			message = "Subject:Account Registration\r\n\r\n"
			message += "Thank you for registering.\r\n"
			message += "To complete your registration please click the following link: "
			message += link + "/" + m.LinkID + "\r\n"
			message += "Please delete this message if you did not try to register an account with us."
		}

		return m.sendMail(message)
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
		message = "Subject:Account Cancellation\r\n\r\n"
		message += "Click the following link to complete the cancellation process: "
		message += m.LinkID + "\r\n"
		message += "Please delete this message if you do not wish to cancel your account."
	}

	return m.sendMail(message)
}

func (m *Mail) OneTimePassword(pwd string, link string) error {
	// If a link is provided check if it is on the white list
	if link != "" && !m.allowedDomain(link) {
		return errors.New("One-time link does not appear to be on the whitelist.")
	}

	var message string
	rxp := regexp.MustCompile(linkPattern)
	rxp2 := regexp.MustCompile(codePattern)
	rxp3 := regexp.MustCompile(userPattern)

	if m.ConfirmMessage != "" {
		message = "Subject:" + m.OneTimeSubject + "\r\n\r\n"
		if link != "" {
			message += rxp.ReplaceAllString(m.OneTimeMessage, link)
		} else {
			message += "You can use your email ({{user}}) and the following code: " + pwd + " to login."
		}
		message = rxp2.ReplaceAllString(message, pwd)
		message = rxp3.ReplaceAllString(message, m.Recipient)
	} else {
		message = "Subject:One time password\r\n\r\n"
		message += "You can use your email (" + m.Recipient + ") and the follwing Code: " + pwd + " to login."
	}

	return m.sendMail(message)
}

// sendMail check the configured smtp mode to invoke the appropriate sendmail command
func (m *Mail) sendMail(message string) error {
	if m.Smtp == "sendmail" {
		return m.unixSendMail(message)
	} else {
		return m.sendSMTP(message)
	}
}

// Generate an SMTP request with the provided message
func (m *Mail) sendSMTP(message string) error {
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

// unixSendMail sends a mail using the mailx commandline program
func (m *Mail) unixSendMail(message string) error {
	content := exec.Command("echo", "-ne", message)
	mailX := exec.Command("sendmail", "-f", m.Sender, m.Recipient)

	r, w := io.Pipe()
	content.Stdout = w
	mailX.Stdin = r

	var mResp bytes.Buffer
	mailX.Stdout = &mResp

	if err := content.Start(); err != nil {
		return err
	}

	if err := mailX.Start(); err != nil {
		return err
	}

	if err := content.Wait(); err != nil {
		return err
	}

	if err := w.Close(); err != nil {
		return err
	}

	if err := mailX.Wait(); err != nil {
		return err
	}

	io.Copy(os.Stdout, &mResp)

	if mResp.String() != "" {
		return errors.New(mResp.String())
	}

	if err := r.Close(); err != nil {
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
