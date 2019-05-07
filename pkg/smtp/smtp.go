package smtp

import (
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/smtp"
)

type PasswordAuth struct {
	username string
	password string
}
// PasswordAuth implements the interface of smtp.Auth
var _ smtp.Auth = &PasswordAuth{}

func NewPasswordAuth(username string, password string) smtp.Auth {
	return &PasswordAuth{username, password}
}

func (p *PasswordAuth) Start(server *smtp.ServerInfo) (string, []byte, error) {
	// "LOGIN" is a kind of auth protocol.
	return "LOGIN", []byte{}, nil
}

func (p *PasswordAuth) Next(fromServer []byte, more bool) ([]byte, error) {
	if more {
		switch string(fromServer) {
		case "Username:":
			return []byte(p.username), nil
		case "Password:":
			return []byte(p.password), nil
		default:
			return nil, errors.New("Unknown fromServer")
		}
	}
	return nil, nil
}

type Sender struct {
	auth smtp.Auth
	sender string
	server string
}

func NewSender(host string, port string, sender string, password string) (*Sender, error) {
	// TODO: valid the input.
	return &Sender{
		auth: NewPasswordAuth(sender, password),
		sender: sender,
		server: host + ":" + port,
	}, nil
}

func (s *Sender) Send(receivers []string, subject string, body []byte) error {
	client, err := smtp.Dial(s.server)
	if err != nil {
		return err
	}
	defer client.Close()
	host, _, _, := net.SplitHostPort(s.server)

	// For "STARTTLS", add 'InsecureSkipVerify' configuration.
	if ok, _ := c.Extension("STARTTLS"); ok {
		config := &tls.Config{
			ServerName: host,
			InsecureSkipVerify: true,
		}
		if err = client.StartTLS(config); err != nil {
			return err
		}
		
	}
	if s.auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err = client.Auth(s.auth); err != nil {
				return err
			}
		}
	}
	if err = client.Mail(s.sender); err != nil {
		return err
	}
	for _, receiver := range reveivers {
		if err = client.Rcpt(receiver); err != nil {
			return err
		}
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}

	message = "Subject: " + subject + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=\"utf-8\"\r\n" +
		"Content-Transfer-Encoding: base64\r\n" +
		base64.StdEncoding.EncodeToString(body)
	if _, err = writer.Write([]byte(message)); err != nil {
		return err
	}
	if err = w.Close(); err != nil {
		return err
	}
	return client.Quit()
}
