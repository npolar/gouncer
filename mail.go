package gouncer

import (
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"regexp"
)

const (
	linkPattern = "{{link}}"
)

type Mail struct {
	Recipient   string
	LinkID      string
	*Core       // Core auth server configuration
	*Backend    // Backend configuration
	*MailConfig // Mail Configuration
}

type MailConfig struct {
	Sender         string // Email address the messages are sent from
	ConfirmSubject string // Confirmation mail subject field
	ConfirmMessage string // Confirmation mail content body
	CancelSubject  string // Cancellation mail subject field
	CancelMessage  string // Cancellation mail content body
}

func NewMailClient(recipient string, linkID string) *Mail {
	return &Mail{
		LinkID:    linkID,
		Recipient: recipient,
	}
}

func (m *Mail) Confirmation() error {
	var message string

	rxp := regexp.MustCompile(linkPattern)

	if m.ConfirmMessage != "" {
		message = "Subject:" + m.ConfirmSubject + "\n\n"
		message += rxp.ReplaceAllString(m.ConfirmMessage, m.GenerateConfirmationLink())
	} else {
		message = "Subject:Account Registration\n\n"
		message += "Thank you for registering.\n\n"
		message += "To complete your registration please click the following link: "
		message += m.GenerateConfirmationLink() + "\n"
		message += "Please delete this message if you did not try to register an account with us."
	}

	return m.SendMail(message)
}

func (m *Mail) Cancellation() error {
	var message string

	rxp := regexp.MustCompile(linkPattern)

	if m.ConfirmMessage != "" {
		message = "Subject:" + m.CancelSubject + "\n\n"
		message += rxp.ReplaceAllString(m.CancelMessage, m.GenerateCancellationLink())
	} else {
		message = "Subject:Account Cancellation\n\n"
		message += "Click the following link to complete the cancellation process: "
		message += m.GenerateCancellationLink() + "\n"
		message += "Please delete this message if you do not wish to cancel your account."
	}

	return m.SendMail(message)
}

func (m *Mail) GenerateConfirmationLink() string {
	return "https://" + m.ResolveHost() + "/confirm/" + m.LinkID
}

func (m *Mail) GenerateCancellationLink() string {
	return "https://" + m.ResolveHost() + "/cancel/" + m.LinkID
}

func (m *Mail) ResolveHost() string {
	// Set host to localhost as default
	host := "localhost"

	// Use the provided hostname if present else try to resolve the localIP
	if m.Hostname != "" {
		host = m.Hostname
	} else {
		if ip, err := m.localIP(); err == nil {
			host = ip.String()
		}
	}

	return host + m.Port
}

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

// localIP tries to resolve the local IP of the server
func (m *Mail) localIP() (net.IP, error) {
	tt, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, t := range tt {
		aa, err := t.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range aa {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			v4 := ipnet.IP.To4()
			if v4 == nil || v4[0] == 127 { // loopback address
				continue
			}
			return v4, nil
		}
	}
	return nil, errors.New("cannot find local IP address")
}
