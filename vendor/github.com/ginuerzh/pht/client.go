package pht

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	Host       string
	Key        string
	httpClient *http.Client
	manager    *sessionManager
}

func NewClient(host, key string) *Client {
	return &Client{
		Host:       host,
		Key:        key,
		httpClient: &http.Client{},
		manager:    newSessionManager(),
	}
}

func (c *Client) Dial() (net.Conn, error) {
	r, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s%s", c.Host, tokenURI), nil)
	if err != nil {
		return nil, err
	}
	r.Header.Set("Authorization", "key="+c.Key)
	resp, err := c.httpClient.Do(r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(resp.Status)
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	token := strings.TrimPrefix(string(data), "token=")
	if token == "" {
		return nil, errors.New("invalid token")
	}

	session := newSession(0, 0)
	c.manager.SetSession(token, session)

	go c.sendDataLoop(token)
	go c.recvDataLoop(token)

	return newConn(session), nil
}

func (c *Client) sendDataLoop(token string) error {
	session := c.manager.GetSession(token)
	if session == nil {
		return errors.New("invalid token")
	}

	for {
		select {
		case b, ok := <-session.wchan:
			var data string
			if len(b) > 0 {
				data = base64.StdEncoding.EncodeToString(b)
			}
			r, err := http.NewRequest(http.MethodPost, fmt.Sprintf("http://%s%s", c.Host, pushURI), bytes.NewBufferString(data+"\n"))
			if err != nil {
				return err
			}
			r.Header.Set("Authorization", fmt.Sprintf("key=%s; token=%s", c.Key, token))
			if !ok {
				c.manager.DelSession(token)
				resp, err := c.httpClient.Do(r)
				if err != nil { // TODO: retry
					return err
				}
				resp.Body.Close()
				return nil // session is closed
			}

			resp, err := c.httpClient.Do(r)
			if err != nil { // TODO: retry
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return errors.New(resp.Status)
			}
		}
	}
}

func (c *Client) recvDataLoop(token string) error {
	session := c.manager.GetSession(token)
	if session == nil {
		return errors.New("invalid token")
	}

	for {
		err := c.recvData(token, session)
		if err != nil {
			close(session.rchan)
			c.manager.DelSession(token)
			return err
		}
	}
}

func (c *Client) recvData(token string, s *session) error {
	r, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://%s%s", c.Host, pollURI), nil)
	if err != nil {
		return err
	}
	r.Header.Set("Authorization", fmt.Sprintf("key=%s; token=%s", c.Key, token))
	resp, err := c.httpClient.Do(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return errors.New(resp.Status)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		select {
		case <-s.closed:
			return errors.New("session closed")
		default:
		}

		b, err := base64.StdEncoding.DecodeString(scanner.Text())
		if err != nil {
			return err
		}
		select {
		case s.rchan <- b:
		case <-s.closed:
			return errors.New("session closed")
		case <-time.After(time.Second * 90):
			return errors.New("timeout")
		}

		if err := scanner.Err(); err != nil {
			return err
		}
	}
	return nil
}
