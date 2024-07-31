package yubihsm

import (
	"bytes"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/indoff/yubihsm-go/commands"
	"github.com/indoff/yubihsm-go/connector"
	"github.com/indoff/yubihsm-go/securechannel"
)

type (
	// SessionManager manages a pool of authenticated secure sessions with a YubiHSM2
	SessionManager struct {
		session   *securechannel.SecureChannel
		lock      sync.Mutex
		connector connector.Connector
		authKeyID uint16
		password  string

		creationWait sync.WaitGroup
		destroyed    bool
		keepAlive    *time.Timer
		swapping     bool
	}
)

var (
	echoPayload = []byte("keepalive")
)

const (
	pingInterval = 15 * time.Second
)

// NewSessionManager creates a new instance of the SessionManager with poolSize connections.
// Wait on channel Connected with a timeout to wait for active connections to be ready.
func NewSessionManager(connector connector.Connector, authKeyID uint16, password string) (*SessionManager, error) {
	manager := &SessionManager{
		connector: connector,
		authKeyID: authKeyID,
		password:  password,
		destroyed: false,
	}

	err := manager.swapSession()
	if err != nil {
		return nil, err
	}

	manager.keepAlive = time.NewTimer(pingInterval)
	go manager.pingRoutine() // TODO: error check

	return manager, err
}

func (s *SessionManager) pingRoutine() {
	for range s.keepAlive.C {
		log.Printf("Keepalive timer tripped for session %d. Sending echo command.\n", s.session.ID)
		command, _ := commands.CreateEchoCommand(echoPayload)

		resp, err := s.SendEncryptedCommand(command)
		if err == nil {
			parsedResp, matched := resp.(*commands.EchoResponse)
			if !matched {
				err = errors.New("invalid response type")
			}
			if !bytes.Equal(parsedResp.Data, echoPayload) {
				err = errors.New("echoed data is invalid")
			}
		} else {
			// Session seems to be dead - reconnect and swap
			log.Printf("Keepalive: session %d seems to be dead. Swapping...\n", s.session.ID)
			err = s.swapSession()
			if err != nil {
				log.Printf("swapping dead session failed; err=%v", err)
			}
		}

		s.keepAlive.Reset(pingInterval)
	}
}

func (s *SessionManager) swapSession() error {
	if s.session != nil {
		log.Printf("Swapping session %d...\n", s.session.ID)
	} else {
		log.Println("Swapping session: No ID, brand new session.")
	}
	// Lock swapping process
	s.swapping = true
	defer func() { s.swapping = false }()

	newSession, err := securechannel.NewSecureChannel(s.connector, s.authKeyID, s.password)
	if err != nil {
		log.Printf("Failed to swap session: %s\n", err.Error())
		return err
	}

	err = newSession.Authenticate()
	if err != nil {
		log.Printf("Failed to swap session: %s\n", err.Error())
		return err
	}

	s.lock.Lock()
	defer s.lock.Unlock()
	if s.session != nil {
		log.Printf("Swapping session %d: Locked session.\n", s.session.ID)
	} else {
		log.Printf("Swapping session: Brand new session. Locked session.")
	}
	// Close old session (must be unlocked first)
	if s.session != nil {
		log.Printf("Swapping session %d: Closing old session.\n", s.session.ID)
		go s.session.Close() // TODO: error check
	}

	// Replace primary session
	s.session = newSession

	return nil
}

func (s *SessionManager) checkSessionHealth() {
	log.Printf("Health check: Session %d: %d / %d messages used.\n", s.session.ID, s.session.Counter, securechannel.MaxMessagesPerSession)
	if s.session.Counter >= securechannel.MaxMessagesPerSession*0.9 && !s.swapping {
		log.Printf("Health check: Session %d: %d / %d messages used. SWAPPING!\n", s.session.ID, s.session.Counter, securechannel.MaxMessagesPerSession)
		go s.swapSession() // TODO: error check
	}
}

// SendEncryptedCommand sends an encrypted & authenticated command to the HSM
// and returns the decrypted and parsed response.
func (s *SessionManager) SendEncryptedCommand(c *commands.CommandMessage) (commands.Response, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	// Check session health after executing the command
	defer s.checkSessionHealth()

	if s.destroyed {
		return nil, errors.New("sessionmanager has already been destroyed")
	}
	if s.session == nil {
		return nil, errors.New("no session available")
	}

	return s.session.SendEncryptedCommand(c)
}

// SendCommand sends an unauthenticated command to the HSM and returns the parsed response
func (s *SessionManager) SendCommand(c *commands.CommandMessage) (commands.Response, error) {
	s.lock.Lock()
	defer s.lock.Unlock()

	if s.destroyed {
		return nil, errors.New("sessionmanager has already been destroyed")
	}
	if s.session == nil {
		return nil, errors.New("no session available")
	}

	return s.session.SendCommand(c)
}

// Destroy closes all connections in the pool.
// SessionManager instances can't be reused.
func (s *SessionManager) Destroy() {
	s.lock.Lock()
	defer s.lock.Unlock()

	s.keepAlive.Stop()
	s.session.Close()
	s.destroyed = true
}

// Returns the session ID. Will return 0 as the ID if there is an error.
func (s *SessionManager) GetSessionID() (uint8, error) {
	if s.session != nil {
		return s.session.ID, nil
	}
	return 0, errors.New("couldn't retrieve session id: no session is open")
}
