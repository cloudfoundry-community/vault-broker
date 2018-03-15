package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jhunt/go-log"
	"github.com/pborman/uuid"
	"github.com/pivotal-cf/brokerapi"
	"github.com/pivotal-golang/lager"
)

var (
	BrokerGUID        string
	BrokerName        string
	BrokerDescription string
	BrokerTags        []string

	PlanName        string
	PlanDescription string

	AuthUsername string
	AuthPassword string

	BackendURL       string
	BackendURLs      []string
	BackendPublic    string
	BackendPublicIPs []string
	BackendToken     string
	BackendInsecure  bool
	BackendRefresh   int

	BackendHealth sync.Map

	Version string
)

type Credentials struct {
	Vault  string   `json:"vault"`
	Vaults []string `json:"vaults"`
	Token  string   `json:"token"`
	Root   string   `json:"root"`
}

func ReadSecret(in io.Reader) (map[string]string, error) {
	m := make(map[string]string)

	b, err := ioutil.ReadAll(in)
	if err != nil {
		return m, err
	}

	var raw struct {
		Data map[string]interface{} `json:"data"`
	}
	err = json.Unmarshal(b, &raw)
	if err != nil {
		return m, err
	}
	for k, v := range raw.Data {
		m[k] = fmt.Sprintf("%v", v)
	}

	return m, nil
}

type VaultBroker struct {
	HTTP *http.Client

	Lock   sync.Mutex
	Tokens map[string]bool
}

func (vault *VaultBroker) NewRequest(method, url string, data interface{}) (*http.Request, error) {
	if data == nil {
		return http.NewRequest(method, url, nil)
	}
	cooked, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return http.NewRequest(method, url, strings.NewReader(string(cooked)))
}

func (vault *VaultBroker) Do(method, url string, data interface{}) (*http.Response, error) {
	for _, backend := range BackendURLs {
		currentStatus, ok := BackendHealth.Load(backend)
		if !ok || currentStatus.(bool) != true {
			continue
		}
		log.Infof("[request %s] using vault at %s", url, backend)
		req, err := vault.NewRequest(method, fmt.Sprintf("%s%s", backend, url), data)
		if err != nil {
			return nil, err
		}

		req.Header.Add("X-Vault-Token", BackendToken)
		res, err := vault.HTTP.Do(req)
		if err != nil {
			log.Errorf("Failed to interact with Vault at %s: %s", backend, err)
		} else if res.StatusCode == 503 {
			log.Errorf("Vault is sealed (HTTP 503)")
		} else {
			return res, nil
		}
	}
	return nil, fmt.Errorf("Could not contact or errored contacting all vaults. Check log for details")
}

func (vault *VaultBroker) List(path string) ([]string, error) {
	res, err := vault.Do("GET", fmt.Sprintf("%s?list=1", path), nil)
	if err != nil {
		return nil, err
	}
	if res.StatusCode == 404 {
		return nil, nil
	}
	if res.StatusCode != 200 {
		return nil, fmt.Errorf("Received %s from Vault", res.Status)
	}

	b, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	var r struct{ Data struct{ Keys []string } }
	if err = json.Unmarshal(b, &r); err != nil {
		return nil, err
	}

	return r.Data.Keys, nil
}

type TokenCreateRequest struct {
	ID              string   `json:"id,omitempty"`
	DisplayName     string   `json:"display_name"`
	Policies        []string `json:"policies,omitempty"`
	NoParent        bool     `json:"no_parent,omitempty"`
	NoDefaultPolicy bool     `json:"no_default_policy,omitempty"`
}

type PolicyCreateRequest struct {
	Rules string `json:"rules"`
}

func (vault *VaultBroker) Scan() error {
	instances, err := vault.List("/v1/secret/acct")
	if err != nil {
		log.Errorf("[scan] error: %s", err)
		return err
	}

	for _, inst := range instances {
		if !strings.HasSuffix(inst, "/") {
			continue
		}
		instanceID := strings.TrimSuffix(inst, "/")
		bindings, err := vault.List(fmt.Sprintf("/v1/secret/acct/%s", instanceID))
		if err != nil {
			log.Errorf("[scan %s] error: %s", instanceID, err)
			continue
		}

		for _, bind := range bindings {
			if strings.HasSuffix(bind, "/") {
				continue
			}
			bindingID := strings.TrimSuffix(bind, "/")

			res, err := vault.Do("GET", fmt.Sprintf("/v1/secret/acct/%s/%s", instanceID, bindingID), nil)
			if err != nil {
				log.Errorf("[scan %s/%s] error: %s", instanceID, bindingID, err)
				continue
			}

			secret, err := ReadSecret(res.Body)
			if err != nil {
				log.Errorf("[scan %s/%s] error: %s", instanceID, bindingID, err)
				continue
			}

			if token, ok := secret["token"]; ok {
				vault.Tokens[token] = true
			}
		}
	}

	log.Infof("[scan] found %d tokens to renew", len(vault.Tokens))
	return nil
}

func (vault *VaultBroker) RenewTokens(interval int) {
	log.Infof("[renew] tokens will be renewed every %d minutes...", interval)
	t := time.Tick(time.Duration(interval) * time.Minute)
	vault.RenewOnce()

	for _ = range t {
		vault.RenewOnce()
	}
}

func (vault *VaultBroker) RenewOnce() {
	vault.Lock.Lock()
	defer vault.Lock.Unlock()

	for token := range vault.Tokens {
		res, err := vault.Do("POST", fmt.Sprintf("/v1/auth/token/renew/%s", token), nil)
		if err != nil {
			log.Errorf("[renew %s] error: %s", token, err)
			continue
		}
		if res.StatusCode != 200 {
			log.Errorf("[renew %s] error: received %s from Vault", token, res.Status)
			continue
		}
		log.Infof("[renew %s] renewed token successfully.", token)
	}
}

func (vault *VaultBroker) Services() []brokerapi.Service {
	log.Infof("[catalog] returning service catalog")
	return []brokerapi.Service{
		brokerapi.Service{
			ID:            BrokerGUID,
			Name:          BrokerName,
			Description:   BrokerDescription,
			Tags:          BrokerTags,
			Bindable:      true,
			PlanUpdatable: false,
			Plans: []brokerapi.ServicePlan{
				brokerapi.ServicePlan{
					ID:          fmt.Sprintf("%s.%s", BrokerGUID, PlanName),
					Name:        PlanName,
					Description: PlanDescription,
					Free:        brokerapi.FreeValue(true),
				},
			},
		},
	}
}

func (vault *VaultBroker) Provision(instanceID string, details brokerapi.ProvisionDetails, asyncAllowed bool) (brokerapi.ProvisionedServiceSpec, error) {
	spec := brokerapi.ProvisionedServiceSpec{IsAsync: false}

	log.Infof("[provision %s] provisioning new service", instanceID)
	log.Infof("[provision %s] using vault at %s", instanceID, BackendURL)
	log.Infof("[provision %s] creating new policy for access to secret/%s", instanceID, instanceID)
	res, err := vault.Do("PUT", fmt.Sprintf("/v1/sys/policy/%s", instanceID),
		PolicyCreateRequest{
			Rules: fmt.Sprintf(`
path "secret/%s" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}
path "secret/%s/*" {
  capabilities = ["create", "read", "update", "delete", "list", "sudo"]
}`, instanceID, instanceID),
		},
	)
	if err != nil {
		log.Errorf("[provision %s] error: %s", instanceID, err)
		return spec, err
	}
	if res.StatusCode != 204 && res.StatusCode != 200 {
		log.Errorf("[provision %s] error: vault returned a %s", instanceID, res.Status)
		return spec, fmt.Errorf("Received %s from Vault", res.Status)
	}

	log.Infof("[provision %s] success", instanceID)
	return spec, nil
}

func (vault *VaultBroker) LastOperation(instanceID string) (brokerapi.LastOperation, error) {
	return brokerapi.LastOperation{}, fmt.Errorf("not implemented")
}

func (vault *VaultBroker) Deprovision(instanceID string, details brokerapi.DeprovisionDetails, asyncAllowed bool) (brokerapi.IsAsync, error) {
	log.Infof("[deprovision %s] removing policy for secret/%s", instanceID, instanceID)
	log.Infof("[deprovision %s] using vault at %s", instanceID, BackendURL)
	res, err := vault.Do("DELETE", fmt.Sprintf("/v1/sys/policy/%s", instanceID), nil)
	if err != nil {
		log.Errorf("[deprovision %s] error: %s", instanceID, err)
		return false, err
	}
	if res.StatusCode != 204 {
		log.Errorf("[deprovision %s] error: vault returned a %s", instanceID, res.Status)
		return false, fmt.Errorf("Received %s from Vault", res.Status)
	}

	var rm func(string)
	rm = func(path string) {
		log.Infof("[deprovision %s] removing secret at %s", instanceID, path)
		_, err := vault.Do("DELETE", path, nil)
		if err != nil {
			log.Errorf("[deprovision %s] unable to delete %s: %s", instanceID, path, err)
		}

		keys, err := vault.List(path)
		if err != nil {
			log.Errorf("[deprovision %s] unable to list %s: %s", instanceID, path, err)
			return
		}

		for _, sub := range keys {
			rm(fmt.Sprintf("%s/%s", path, strings.TrimSuffix(sub, "/")))
		}
	}
	log.Infof("[deprovision %s] clearing out secrets", instanceID)
	rm(fmt.Sprintf("/v1/secret/%s", instanceID))

	log.Infof("[deprovision %s] success", instanceID)
	return false, nil
}

func (vault *VaultBroker) Bind(instanceID, bindingID string, details brokerapi.BindDetails) (brokerapi.Binding, error) {
	var binding brokerapi.Binding

	log.Infof("[bind %s / %s] binding service", instanceID, bindingID)
	log.Infof("[bind %s / %s] using vault at %s", instanceID, bindingID, BackendURL)
	log.Infof("[bind %s / %s] generating new access token for bound application", instanceID, bindingID)
	token := uuid.NewRandom().String()
	res, err := vault.Do("POST", "/v1/auth/token/create",
		TokenCreateRequest{
			ID:              token,
			DisplayName:     fmt.Sprintf("%s/%s", instanceID, bindingID),
			Policies:        []string{instanceID},
			NoParent:        true,
			NoDefaultPolicy: true,
		})
	if err != nil {
		log.Errorf("[bind %s / %s] error: %s", instanceID, bindingID, err)
		return binding, err
	}
	if res.StatusCode != 200 {
		log.Errorf("[bind %s / %s] error: vault returned a %s", instanceID, bindingID, res.Status)
		return binding, fmt.Errorf("Received %s from Vault", res.Status)
	}

	/* store the instance / binding ID in Vault */
	log.Infof("[bind %s / %s] saving accounting records", instanceID, bindingID)
	res, err = vault.Do("POST",
		fmt.Sprintf("/v1/secret/acct/%s/%s", instanceID, bindingID),
		map[string]string{"token": token},
	)
	if err != nil {
		log.Errorf("[bind %s / %s] error: %s", instanceID, bindingID, err)
		return binding, err
	}
	if res.StatusCode != 204 {
		log.Errorf("[bind %s / %s] error: vault returned a %s", instanceID, bindingID, res.Status)
		return binding, fmt.Errorf("Received %s from Vault", res.Status)
	}

	vault.Lock.Lock()
	vault.Tokens[token] = true
	vault.Lock.Unlock()

	log.Infof("[bind %s / %s] success", instanceID, bindingID)
	binding.Credentials = Credentials{
		Vault:  BackendPublic,
		Vaults: BackendPublicIPs,
		Token:  token,
		Root:   fmt.Sprintf("secret/%s", instanceID),
	}
	return binding, nil
}

func (vault *VaultBroker) Unbind(instanceID, bindingID string, details brokerapi.UnbindDetails) error {
	log.Infof("[unbind %s / %s] unbinding service", instanceID, bindingID)
	log.Infof("[unbind %s / %s] using vault at %s", instanceID, bindingID, BackendURL)
	log.Infof("[unbind %s / %s] retrieving access token", instanceID, bindingID)
	res, err := vault.Do("GET",
		fmt.Sprintf("/v1/secret/acct/%s/%s", instanceID, bindingID), nil)
	if err != nil {
		log.Errorf("[unbind %s / %s] error: %s", instanceID, bindingID, err)
		return err
	}
	if res.StatusCode != 200 {
		log.Errorf("[unbind %s / %s] error: vault returned a %s", instanceID, bindingID, res.Status)
		return fmt.Errorf("Received %s from Vault", res.Status)
	}

	secret, err := ReadSecret(res.Body)
	if err != nil {
		log.Errorf("[unbind %s / %s] error: %s", instanceID, bindingID, err)
		return err
	}
	if _, ok := secret["token"]; !ok {
		log.Errorf("[unbind %s / %s] error: `token` key not found at secret/acct/%s/%s", instanceID, bindingID, instanceID, bindingID)
		return fmt.Errorf("No token found for given service bind (%s)", bindingID)
	}

	log.Infof("[unbind %s / %s] revoking token '%s'", instanceID, bindingID, secret["token"])
	res, err = vault.Do("PUT", "/v1/auth/token/revoke", map[string]string{"token": secret["token"]})
	if err != nil {
		log.Errorf("[unbind %s / %s] error: %s", instanceID, bindingID, err)
		return err
	}
	if res.StatusCode != 204 {
		log.Errorf("[unbind %s / %s] error: vault returned a %s", instanceID, bindingID, res.Status)
		return fmt.Errorf("Received %s from Vault", res.Status)
	}

	log.Infof("[unbind %s / %s] removing accounting records", instanceID, bindingID)
	res, err = vault.Do("DELETE",
		fmt.Sprintf("/v1/secret/acct/%s/%s", instanceID, bindingID), nil)
	if err != nil {
		log.Errorf("[unbind %s / %s] error: %s", instanceID, bindingID, err)
		return err
	}
	if res.StatusCode != 204 {
		log.Errorf("[unbind %s / %s] error: vault returned a %s", instanceID, bindingID, res.Status)
		return fmt.Errorf("Received %s from Vault", res.Status)
	}

	vault.Lock.Lock()
	delete(vault.Tokens, secret["token"])
	vault.Lock.Unlock()

	log.Infof("[unbind %s / %s] success", instanceID, bindingID)
	return nil
}

func (vault *VaultBroker) Update(instanceID string, details brokerapi.UpdateDetails, asyncAllowed bool) (brokerapi.IsAsync, error) {
	// Update instance here
	return false, fmt.Errorf("not implemented")
}

func (vault *VaultBroker) HealthCheck() {
	log.Infof("[health] health will be performed every 30 seconds...")
	t := time.Tick(time.Duration(30) * time.Second)
	vault.checkBackendHealth()

	for _ = range t {
		vault.checkBackendHealth()
	}
}

func (vault *VaultBroker) checkBackendHealth() {
	for _, backend := range BackendURLs {
		currentStatus, ok := BackendHealth.Load(backend)
		if !ok {
			log.Errorf("[health] Backend %s not found in health map...skipping")
		}
		healthy := true
		res, err := vault.HTTP.Get(fmt.Sprintf("%s%s", backend, "/v1/sys/health?standbyok=true"))
		if err != nil || res.StatusCode != 200 {
			healthy = false
		}
		if currentStatus.(bool) != healthy {
			log.Warnf("[health] Vault at %s is now marked as healthy:%t", backend, healthy)
			BackendHealth.Store(backend, healthy)
		}
	}
}

func usage(rc int) {
	version()
	fmt.Printf(`USAGE: vault-broker [-h|-v]

Options:

  -h, --help     Print this help screen and exit.
  -v, --version  Print the version and exit.

Environment Variables:

  BROKER_GUID    GUID to use when registering the broker with Cloud Foundry
                 Defaults to 'f89443a4-ae71-49b0-b726-23ee9c98ae6d'

  SERVICE_NAME   Name of the service, as shown in the marketplace.
                 Defaults to 'vault'

  SERVICE_DESC   A description of the service, also for the marketplace.
                 Defaults to 'Vault Secure Storage'

  SERVICE_TAGS   A set of tags for the service, each separated by a comma
                 followed by a space.  By default, no tags are configured.

  AUTH_USERNAME  The username for authenticating with Cloud Foundry.
                 Defaults to 'vault'.

  AUTH_PASSWORD  The password for authenticating with Cloud Foundry.
                 Also defaults to 'vault'.

 *VAULT_ADDR     The address to use when accessing the Vault to set up new
                 policies and manage provisioned services.
                 This variable is REQUIRED.

  VAULT_ADVERTISE_ADDR
                 The address to hand out to bound applications, along with
                 their credentials.  This defaults to '$VAULT_ADDR', but can
                 be set separately if you need or want applications to access
                 the Vault via DNS, or over a load balancer.

 *VAULT_TOKEN    The token that the service broker will use when interacting
                 with the Vault.  This variable is REQUIRED, and you probably
                 want to set it to a root token.

  VAULT_SKIP_VERIFY
                 Instructs the broker to ignore SSL/TLS certificate problems
                 (self-signedness, domain mismatch, expiration, etc.).
                 Set this at your own risk.  Note that this will not be
                 propagated to bound applications.

  VAULT_REFRESH_INTERVAL
                 The Vault Broker regularly refreshes auth tokens it has
                 given to bound applications, so that they can continue to
                 use tokens without worrying about leases or TTLs.  This sets
                 the time (in minutes) between refresh attempts.
`)
	os.Exit(rc)
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

func version() {
	v := "(development version)"
	if Version != "" {
		v = fmt.Sprintf("v%s", Version)
	}
	fmt.Printf("vault-broker %s\n", v)
}

func main() {
	ok := true

	log.SetupLogging(log.LogConfig{
		Type:  "console",
		Level: "info",
	})

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-h":
			usage(0)
		case "-?":
			usage(0)
		case "--help":
			usage(0)
		case "help":
			usage(0)

		case "-v":
			version()
			os.Exit(0)
		case "--version":
			version()
			os.Exit(0)
		case "version":
			version()
			os.Exit(0)

		default:
			usage(1)
		}
	}

	BrokerGUID = os.Getenv("BROKER_GUID")
	if BrokerGUID == "" {
		BrokerGUID = "f89443a4-ae71-49b0-b726-23ee9c98ae6d"
	}

	BrokerName = os.Getenv("SERVICE_NAME")
	if BrokerName == "" {
		BrokerName = "vault"
	}

	BrokerDescription = os.Getenv("SERVICE_DESC")
	if BrokerDescription == "" {
		BrokerDescription = "Vault Secure Storage"
	}

	if os.Getenv("SERVICE_TAGS") != "" {
		BrokerTags = strings.Split(os.Getenv("SERVICE_TAGS"), ", ")
	}

	PlanName = os.Getenv("SERVICE_PLAN")
	if PlanName == "" {
		PlanName = "shared"
	}
	PlanDescription = "Secure access to a shared segment of a Vault (secret/ backend only)"

	AuthUsername = os.Getenv("AUTH_USERNAME")
	if AuthUsername == "" {
		AuthUsername = "vault"
	}

	AuthPassword = os.Getenv("AUTH_PASSWORD")
	if AuthPassword == "" {
		AuthPassword = "vault"
	}

	BackendURL = os.Getenv("VAULT_ADDR")
	if BackendURL == "" {
		fmt.Fprintf(os.Stderr, "No VAULT_ADDR environment variable set!\n")
		ok = false
	}

	BackendPublic = os.Getenv("VAULT_ADVERTISE_ADDR")
	if BackendPublic == "" {
		BackendPublic = BackendURL
	}

	BackendURLs = strings.Split(strings.Replace(os.Getenv("VAULT_ADDRS"), " ", "", -1), ",")
	if os.Getenv("VAULT_ADDRS") == "" {
		BackendURLs = []string{BackendURL}
	}

	if !stringInSlice(BackendURL, BackendURLs) {
		BackendURLs = append([]string{BackendURL}, BackendURLs...)
	}

	BackendPublicIPs = strings.Split(strings.Replace(os.Getenv("VAULT_ADVERTISE_ADDRS"), " ", "", -1), ",")
	if os.Getenv("VAULT_ADVERTISE_ADDRS") == "" {
		BackendPublicIPs = BackendURLs
	}

	// Initialize map of backend health to initially be true
	for i := 0; i < len(BackendURLs); i++ {
		BackendHealth.Store(BackendURLs[i], true)
	}

	BackendToken = os.Getenv("VAULT_TOKEN")
	if BackendToken == "" {
		fmt.Fprintf(os.Stderr, "No VAULT_TOKEN environment variable set!\n")
		ok = false
	}

	if os.Getenv("VAULT_SKIP_VERIFY") != "" {
		BackendInsecure = true
	}

	BackendRefresh = 30
	if s := os.Getenv("VAULT_REFRESH_INTERVAL"); s != "" {
		v, err := strconv.ParseInt(s, 10, 64)
		if err != nil || v <= 0 {
			fmt.Fprintf(os.Stderr, "Invalid VAULT_REFRESH_INTERVAL value (%s); must be a non-zero, positive number or minutes", s)
			ok = false
		} else {
			BackendRefresh = int(v)
		}
	}

	if !ok {
		fmt.Fprintf(os.Stderr, "Errors encountered during startup.\n")
		os.Exit(1)
	}

	log.Infof("BackendURL: %s - BackendURLs: %v - BackendPublic: %s - BackendPublicIPs: %v", BackendURL, BackendURLs, BackendPublic, BackendPublicIPs)

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	bind := fmt.Sprintf(":%s", port)

	vault := &VaultBroker{
		HTTP: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: BackendInsecure,
				},
				DisableKeepAlives: true,
			},
			Timeout: 5 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) > 10 {
					return fmt.Errorf("stopped after 10 redirects")
				}
				req.Header.Add("X-Vault-Token", BackendToken)
				return nil
			},
		},
		Tokens: make(map[string]bool),
	}

	go vault.HealthCheck()
	vault.Scan()
	go vault.RenewTokens(BackendRefresh)
	log.Infof("Vault Service Broker listening on %s", bind)
	http.Handle("/", brokerapi.New(
		vault,
		lager.NewLogger("vault-broker"),
		brokerapi.BrokerCredentials{
			Username: AuthUsername,
			Password: AuthPassword,
		}))
	http.ListenAndServe(bind, nil)
}
