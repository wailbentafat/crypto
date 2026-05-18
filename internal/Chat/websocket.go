package chat

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

type WSMessage struct {
	Type      string    `json:"type"`
	RoomID    string    `json:"room_id,omitempty"`
	Username  string    `json:"username"`
	Content   string    `json:"content,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	Key       string    `json:"key,omitempty"`
}

type Client struct {
	conn      *websocket.Conn
	send      chan []byte
	username  string
	roomID    string
	key       []byte
}

type Room struct {
	roomID    string
	clients   map[*Client]bool
	broadcast chan []byte
	register  chan *Client
	unregister chan *Client
	mutex     sync.RWMutex
}

type ChatServer struct {
	rooms      map[string]*Room
	roomsMutex sync.RWMutex
}

func NewChatServer() *ChatServer {
	return &ChatServer{
		rooms: make(map[string]*Room),
	}
}

func (cs *ChatServer) getOrCreateRoom(roomID string) *Room {
	cs.roomsMutex.Lock()
	defer cs.roomsMutex.Unlock()

	if room, exists := cs.rooms[roomID]; exists {
		return room
	}

	room := &Room{
		roomID:    roomID,
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}

	cs.rooms[roomID] = room

	go func() {
		for {
			select {
			case client := <-room.register:
				room.mutex.Lock()
				room.clients[client] = true
				room.mutex.Unlock()
				fmt.Printf("User %s joined room %s\n", client.username, room.roomID)

			case client := <-room.unregister:
				room.mutex.Lock()
				if _, ok := room.clients[client]; ok {
					delete(room.clients, client)
					close(client.send)
				}
				room.mutex.Unlock()
				fmt.Printf("User %s left room %s\n", client.username, room.roomID)

			case message := <-room.broadcast:
				room.mutex.RLock()
				for client := range room.clients {
					select {
					case client.send <- message:
					default:
						close(client.send)
						delete(room.clients, client)
					}
				}
				room.mutex.RUnlock()
			}
		}
	}()

	return room
}

func (cs *ChatServer) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	roomID := r.URL.Query().Get("room")
	username := r.URL.Query().Get("username")

	if roomID == "" {
		roomID = "default"
	}
	if username == "" {
		username = "Anonymous"
	}

	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("WebSocket upgrade error: %v\n", err)
		return
	}

	key := make([]byte, 32)
	rand.Read(key)

	client := &Client{
		conn:     ws,
		send:     make(chan []byte, 256),
		username: username,
		roomID:   roomID,
		key:      key,
	}

	room := cs.getOrCreateRoom(roomID)
	room.register <- client

	go client.writePump()
	go client.readPump(cs, room)
}

func (c *Client) readPump(cs *ChatServer, room *Room) {
	defer func() {
		room.unregister <- c
		c.conn.Close()
	}()

	c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	c.conn.SetPongHandler(func(string) error {
		c.conn.SetReadDeadline(time.Now().Add(60 * time.Second))
		return nil
	})

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
				fmt.Printf("WebSocket error: %v\n", err)
			}
			break
		}

		var wsMsg WSMessage
		if err := json.Unmarshal(message, &wsMsg); err != nil {
			continue
		}

		_, _ = c.encryptMessage(wsMsg.Content)

		response := WSMessage{
			Type:      "message",
			RoomID:    c.roomID,
			Username:  c.username,
			Content:   wsMsg.Content,
			Timestamp: time.Now(),
		}

		responseBytes, _ := json.Marshal(response)
		room.broadcast <- responseBytes
	}
}

func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				return
			}

			w, err := c.conn.NextWriter(websocket.TextMessage)
			if err != nil {
				return
			}
			w.Write(message)

			if err := w.Close(); err != nil {
				return
			}

		case <-ticker.C:
			c.conn.SetWriteDeadline(time.Now().Add(10 * time.Second))
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				return
			}
		}
	}
}

func wsPKCS7Pad(data []byte) []byte {
	padding := aes.BlockSize - len(data)%aes.BlockSize
	pad := make([]byte, padding)
	for i := range pad {
		pad[i] = byte(padding)
	}
	return append(data, pad...)
}

func wsPKCS7Unpad(data []byte) []byte {
	if len(data) == 0 {
		return data
	}
	p := int(data[len(data)-1])
	if p == 0 || p > aes.BlockSize || p > len(data) {
		return data
	}
	return data[:len(data)-p]
}

func (c *Client) encryptMessage(plaintext string) (string, string) {
	block, _ := aes.NewCipher(c.key)
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)

	padded := wsPKCS7Pad([]byte(plaintext))
	ciphertext := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, padded)

	encrypted := hex.EncodeToString(iv) + ":" + hex.EncodeToString(ciphertext)
	mac := computeHMAC(plaintext, c.key)

	return encrypted, mac
}

func (c *Client) decryptMessage(encrypted string) string {
	parts := split2(encrypted, ":")
	if len(parts) != 2 {
		return encrypted
	}

	iv, _ := hex.DecodeString(parts[0])
	ciphertext, _ := hex.DecodeString(parts[1])
	if len(iv) != aes.BlockSize || len(ciphertext)%aes.BlockSize != 0 || len(ciphertext) == 0 {
		return encrypted
	}

	block, _ := aes.NewCipher(c.key)
	plaintext := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext, ciphertext)

	return string(wsPKCS7Unpad(plaintext))
}

func split2(s, sep string) []string {
	for i := 0; i < len(s); i++ {
		if i+len(sep) <= len(s) && s[i:i+len(sep)] == sep {
			return []string{s[:i], s[i+len(sep):]}
		}
	}
	return []string{s, ""}
}

func (cs *ChatServer) GetRoomInfo(roomID string) map[string]interface{} {
	cs.roomsMutex.RLock()
	defer cs.roomsMutex.RUnlock()

	room, exists := cs.rooms[roomID]
	if !exists {
		return map[string]interface{}{
			"exists": false,
		}
	}

	room.mutex.RLock()
	defer room.mutex.RUnlock()

	users := make([]string, 0)
	for client := range room.clients {
		users = append(users, client.username)
	}

	return map[string]interface{}{
		"exists":      true,
		"user_count": len(users),
		"users":       users,
	}
}

var globalChatServer = NewChatServer()

func GetGlobalChatServer() *ChatServer {
	return globalChatServer
}

func HandleWebSocketConnection(w http.ResponseWriter, r *http.Request) {
	globalChatServer.HandleWebSocket(w, r)
}

type RoomInfo struct {
	RoomID   string   `json:"room_id"`
	Users    []string `json:"users"`
	UserCount int     `json:"user_count"`
}

func GetRoomsInfo() []RoomInfo {
	globalChatServer.roomsMutex.RLock()
	defer globalChatServer.roomsMutex.RUnlock()

	rooms := make([]RoomInfo, 0)
	for roomID, room := range globalChatServer.rooms {
		room.mutex.RLock()
		users := make([]string, 0)
		for client := range room.clients {
			users = append(users, client.username)
		}
		room.mutex.RUnlock()

		rooms = append(rooms, RoomInfo{
			RoomID:   roomID,
			Users:    users,
			UserCount: len(users),
		})
	}

	return rooms
}