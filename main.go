package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	oidc "github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
)

var (
	issuerURL    = flag.String("issuer-url", "https://accounts.google.com", "")
	clientID     = flag.String("client-id", "", "")
	clientSecret = flag.String("client-secret", "", "")
)

func getStoragePath() string {
	return filepath.Join(getConfigPath(), "git-oidc")
}

func getConfigPath() string {
	if runtime.GOOS == "windows" {
		return os.Getenv("APPDATA")
	}
	if runtime.GOOS == "darwin" {
		return filepath.Join(os.Getenv("HOME"), "Library/Application Support")
	}

	if os.Getenv("XDG_CONFIG_HOME") != "" {
		return os.Getenv("XDG_CONFIG_HOME")
	} else {
		return filepath.Join(os.Getenv("HOME"), ".config")
	}
}

type State struct {
	IDToken      string `json:"id_token"`
	RefreshToken string `json:"refresh_token"`
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func LoadState() (*State, error) {
	path := getStoragePath()
	path = filepath.Join(path, "oidc.json")
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return &State{}, err
	}
	var res State
	if err := json.Unmarshal(data, &res); err != nil {
		return &State{}, err
	}

	return &res, nil
}

func SaveState(c *State) {
	data, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		panic(err)
	}

	path := getStoragePath()
	os.MkdirAll(path, 0700)
	path = filepath.Join(path, "oidc.json")
	err = ioutil.WriteFile(path, data, 0600)
	if err != nil {
		panic(err)
	}
}

var (
	provider        *oidc.Provider
	verifier        *oidc.IDTokenVerifier
	oauthConfig     *oauth2.Config
	state           *State
	csrfToken       string
	callbackChannel chan string
)

func refreshToken(s *State) (string, error) {
	v := url.Values{}
	v.Set("client_id", s.ClientID)
	v.Set("client_secret", s.ClientSecret)
	v.Set("refresh_token", s.RefreshToken)
	v.Set("grant_type", "refresh_token")
	resp, err := http.DefaultClient.PostForm(provider.Endpoint().TokenURL, v)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", fmt.Errorf("http status %d, body %s", resp.StatusCode, body)
	}
	var r struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&r); err != nil {
		return "", err
	}
	return r.IDToken, nil
}

func verifyIDToken(rawIDToken string) error {
	// Parse and verify ID Token payload.
	idToken, err := verifier.Verify(context.Background(), rawIDToken)
	if err != nil {
		return err
	}

	// Extract custom claims
	var claims struct {
		Email    string `json:"email"`
		Verified bool   `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil {
		return err
	}

	return nil
}

func HandleLoginCallback(rw http.ResponseWriter, r *http.Request) {
	if csrfToken != r.URL.Query().Get("state") {
		http.Error(rw, "Invalid state", http.StatusBadRequest)
		return
	}
	callbackChannel <- r.URL.Query().Get("code")
	rw.WriteHeader(http.StatusOK)
	rw.Write([]byte("Done! You can close this window and check your terminal now."))
}

func generateRandomState() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(bytes[:])
}

func handleStore() {
}

func handleErase() {
}

func openBrowser(url string) {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		log.Fatal(err)
	}

}
func handleLogin() {
	flag.CommandLine.Parse(os.Args[2:])

	state = &State{
		IssuerURL:    *issuerURL,
		ClientID:     *clientID,
		ClientSecret: *clientSecret,
	}
	if state.IssuerURL == "" {
		log.Fatalf("Missing --issuer-url")
	}
	if state.ClientID == "" {
		log.Fatalf("Missing --client-id")
	}
	if state.ClientSecret == "" {
		log.Fatalf("Missing --client-secret")
	}
	initOIDC()

	go func() {
		http.HandleFunc("/callback", HandleLoginCallback)
		if err := http.ListenAndServe(":9281", nil); err != nil {
			panic(err)
		}
	}()

	callbackChannel = make(chan string)
	csrfToken = generateRandomState()
	loginURL := oauthConfig.AuthCodeURL(csrfToken, oauth2.AccessTypeOffline, oauth2.SetAuthURLParam("prompt", "consent"))
	openBrowser(loginURL)

	code := <-callbackChannel

	oauth2Token, err := oauthConfig.Exchange(context.Background(), code)
	if err != nil {
		log.Fatal(err)
	}

	// Extract the ID Token from OAuth2 token.
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		log.Fatal("Could not get id_token from oauth2 token")
	}

	if err := verifyIDToken(rawIDToken); err != nil {
		log.Fatal(err)
	}

	state.IDToken = rawIDToken
	state.RefreshToken = oauth2Token.RefreshToken
	SaveState(state)
	log.Println("Login successful!")
}

var commands = map[string]func(){
	"get":   handleGet,
	"store": handleStore,
	"erase": handleErase,
	"login": handleLogin,
}

func main() {
	if len(os.Args) < 2 {
		log.Fatal("Missing command")
	}

	cmd := os.Args[1]
	fn, ok := commands[cmd]
	if !ok {
		log.Fatalf("Unknown command %s", cmd)
	}
	fn()
}

func initOIDC() {
	var err error
	provider, err = oidc.NewProvider(context.Background(), state.IssuerURL)
	if err != nil {
		panic(err)
	}

	verifier = provider.Verifier(&oidc.Config{ClientID: state.ClientID})

	oauthConfig = &oauth2.Config{
		ClientID:     state.ClientID,
		ClientSecret: state.ClientSecret,
		RedirectURL:  "http://localhost:9281/callback",
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile", "email"},
	}
}

func handleGet() {
	var err error
	state, err = LoadState()
	if err != nil {
		panic(err)
	}
	initOIDC()

	if err := verifyIDToken(state.IDToken); err != nil {
		if state.RefreshToken == "" {
			panic("Token invalid and No refresh token")
		}
		log.Println(err)
		log.Println("oidc: Refreshing token.")
		newToken, err := refreshToken(state)
		if err != nil {
			panic(err)
		}
		state.IDToken = newToken
		SaveState(state)
	}

	fmt.Printf("username=%s\n", "_oidc")
	fmt.Printf("password=%s\n", state.IDToken)
}
