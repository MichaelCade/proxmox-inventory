package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type Config struct {
	BaseURL  string
	Username string
	Password string
}

type Version struct {
	Version string `json:"version"`
	Release string `json:"release"`
	Repoid  string `json:"repoid"`
}

type VM struct {
	ID     int    `json:"vmid"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

var (
	config Config
	vmData []VM
)

func main() {
	// Load configuration
	config = Config{
		BaseURL:  os.Getenv("PROXMOX_URL"),
		Username: os.Getenv("PROXMOX_USER"),
		Password: os.Getenv("PROXMOX_PASS"),
	}

	// Log the loaded environment variables (excluding sensitive information)
	log.Printf("Loaded configuration: BaseURL=%s, Username=%s", config.BaseURL, config.Username)

	if config.BaseURL == "" || config.Username == "" || config.Password == "" {
		log.Fatal("Missing required environment variables: PROXMOX_URL, PROXMOX_USER, PROXMOX_PASS")
	}

	// Authenticate and fetch Proxmox version
	ticket, csrfToken, err := authenticate()
	if err != nil {
		log.Fatalf("Failed to authenticate: %v", err)
	}

	version, err := fetchProxmoxVersion(ticket, csrfToken)
	if err != nil {
		log.Fatalf("Failed to fetch Proxmox version: %v", err)
	}

	fmt.Printf("Proxmox Version: %s, Release: %s, Repoid: %s\n", version.Version, version.Release, version.Repoid)

	// Fetch VM data
	vmData, err = fetchVMs(ticket, csrfToken)
	if err != nil {
		log.Fatalf("Failed to fetch VMs: %v", err)
	}

	// Start the HTTP server
	http.HandleFunc("/api/data", handleDataEndpoint)
	log.Println("Starting server on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// handleDataEndpoint serves the VM data in JSON format.
func handleDataEndpoint(w http.ResponseWriter, r *http.Request) {
	log.Println("Received request on /api/data")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(vmData); err != nil {
		log.Printf("Failed to encode VM data: %v", err)
		http.Error(w, fmt.Sprintf("Failed to encode VM data: %v", err), http.StatusInternalServerError)
	}
}

// authenticate logs in to Proxmox API and retrieves a session token.
func authenticate() (string, string, error) {
	authURL := fmt.Sprintf("%s/api2/json/access/ticket", config.BaseURL)

	// URL-encode username and password to handle special characters like !
	escapedUsername := url.QueryEscape(config.Username)
	escapedPassword := url.QueryEscape(config.Password)

	// Prepare login request payload with URL-encoded values
	payload := fmt.Sprintf("username=%s&password=%s", escapedUsername, escapedPassword)
	log.Printf("Authenticating with Proxmox at %s", authURL)

	req, err := http.NewRequest("POST", authURL, strings.NewReader(payload))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Use the custom HTTP client that ignores certificate validation
	client := createHTTPClient()

	resp, err := client.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	// Log the status and the response body for debugging
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Failed to authenticate. Status: %d, Response: %s", resp.StatusCode, body)
		return "", "", fmt.Errorf("failed to authenticate, status: %d", resp.StatusCode)
	}

	// Decode the response to get the ticket and CSRF token
	var response struct {
		Data struct {
			Ticket              string `json:"ticket"`
			CSRFPreventionToken string `json:"CSRFPreventionToken"`
		} `json:"data"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode response: %w", err)
	}

	return response.Data.Ticket, response.Data.CSRFPreventionToken, nil
}

// fetchProxmoxVersion fetches the Proxmox version from the API
func fetchProxmoxVersion(ticket, csrfToken string) (*Version, error) {
	url := fmt.Sprintf("%s/api2/json/version", config.BaseURL)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", fmt.Sprintf("PVEAuthCookie=%s", ticket))
	req.Header.Set("CSRFPreventionToken", csrfToken)

	// Use the custom HTTP client that ignores certificate validation
	client := createHTTPClient()

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Failed to fetch version. Status: %d, Response: %s", resp.StatusCode, body)
		return nil, fmt.Errorf("failed to fetch version, status: %d", resp.StatusCode)
	}

	var response struct {
		Data Version `json:"data"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return &response.Data, nil
}

// fetchVMs fetches the list of VMs from Proxmox API
func fetchVMs(ticket, csrfToken string) ([]VM, error) {
	nodes, err := fetchNodes(ticket, csrfToken)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch nodes: %w", err)
	}

	var vmData []VM
	for _, node := range nodes {
		vms, err := fetchNodeVMs(node, ticket, csrfToken)
		if err != nil {
			return nil, fmt.Errorf("failed to fetch VMs for node %s: %w", node, err)
		}
		vmData = append(vmData, vms...)
	}
	return vmData, nil
}

// fetchNodes fetches the list of nodes from Proxmox API
func fetchNodes(ticket, csrfToken string) ([]string, error) {
	nodesURL := fmt.Sprintf("%s/api2/json/nodes", config.BaseURL)
	req, err := http.NewRequest("GET", nodesURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", fmt.Sprintf("PVEAuthCookie=%s", ticket))
	req.Header.Set("CSRFPreventionToken", csrfToken)

	client := createHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Failed to fetch nodes. Status: %d, Response: %s", resp.StatusCode, body)
		return nil, fmt.Errorf("failed to fetch nodes, status: %d", resp.StatusCode)
	}

	var response struct {
		Data []struct {
			Node string `json:"node"`
		} `json:"data"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var nodes []string
	for _, node := range response.Data {
		nodes = append(nodes, node.Node)
	}
	return nodes, nil
}

// fetchNodeVMs fetches the list of VMs for a given node from Proxmox API
func fetchNodeVMs(node, ticket, csrfToken string) ([]VM, error) {
	vmsURL := fmt.Sprintf("%s/api2/json/nodes/%s/qemu", config.BaseURL, node)
	req, err := http.NewRequest("GET", vmsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Cookie", fmt.Sprintf("PVEAuthCookie=%s", ticket))
	req.Header.Set("CSRFPreventionToken", csrfToken)

	client := createHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		log.Printf("Failed to fetch VMs for node %s. Status: %d, Response: %s", node, resp.StatusCode, body)
		return nil, fmt.Errorf("failed to fetch VMs for node %s, status: %d", node, resp.StatusCode)
	}

	var response struct {
		Data []struct {
			Vmid   int    `json:"vmid"`
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"data"`
	}
	err = json.NewDecoder(resp.Body).Decode(&response)
	if err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	var vms []VM
	for _, vm := range response.Data {
		vms = append(vms, VM{
			ID:     vm.Vmid,
			Name:   vm.Name,
			Status: vm.Status,
		})
	}
	return vms, nil
}

// createHTTPClient creates an HTTP client that ignores certificate validation
func createHTTPClient() *http.Client {
	// Create a custom transport that disables certificate verification
	transport := &http.Transport{
		// Disable certificate verification (not recommended for production)
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	return &http.Client{Transport: transport}
}
