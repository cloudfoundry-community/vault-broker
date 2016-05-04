build:
	go build .

push:
	cf push vault-broker -m 128M -k 256M --no-start
	cf set-env vault-broker VAULT_ADDR "$(VAULT_ADDR)"
	cf set-env vault-broker VAULT_TOKEN "$(shell cat ~/.vault-token)"
	cf start vault-broker

register:
	cf create-service-broker vault vault vault http://vault-broker.bosh-lite.com
	cf enable-service-access vault
