#!/bin/bash -xe
set -x
vault_version=${1:-'1.2.2'}
vault_path="/etc/vault"
yum update -y
yum install unzip -y
yum install -y unzip jq netcat nginx
# Download and install Vault
cd /tmp && \
  curl -sLO https://releases.hashicorp.com/vault/${vault_version}/vault_${vault_version}_linux_amd64.zip && \
  unzip vault_${vault_version}_linux_amd64.zip && \
  mv vault /usr/bin/vault && \
  rm vault_${vault_version}_linux_amd64.zip
  sudo chmod 0755 /usr/bin/vault
  sudo chown root:root /usr/bin/vault
  sudo setcap cap_ipc_lock=+ep /usr/bin/vault

  echo "# Create Vault User and Directories"
  echo "-----------------------------------------"
  # Create dir
  sudo mkdir -p /etc/vault
  sudo mkdir -p /var/lib/vault/data
  # Create Vault User
  sudo useradd --system --home /etc/vault --shell /bin/false vault || true
  sudo chown -R vault:vault /etc/vault /var/lib/vault/

# Install Stackdriver for logging
curl -sSL https://dl.google.com/cloudagents/install-logging-agent.sh | bash

# Systemd service
cat - > /etc/systemd/system/vault.service <<'EOF'
[Unit]
Description="HashiCorp Vault - A tool for managing secrets"
Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target
ConditionFileNotEmpty=/etc/vault/config.hcl

[Service]
User=vault
Group=vault
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
SecureBits=keep-caps
AmbientCapabilities=CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart=/usr/bin/vault server -config=/etc/vault/config.hcl
ExecReload=/bin/kill --signal HUP
KillMode=process
KillSignal=SIGINT
Restart=on-failure
RestartSec=5
TimeoutStopSec=30
StartLimitBurst=3
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
EOF
chmod 0600 /etc/systemd/system/vault.service
# Add the Configuration
cat - > /etc/vault/config.hcl <<'EOF'
disable_cache = true
disable_mlock = true
ui = true
listener "tcp" {
   address          = "0.0.0.0:8200"
   tls_disable      = 1
}
storage "gcs" {
   bucket  = "vault-storage"
   ha_enabled    = "true"
 }
api_addr = "http://127.0.0.1:8200"
cluster_address = "http://127.0.0.1:8201"
max_lease_ttl         = "10h"
default_lease_ttl    = "10h"
cluster_name         = "vault"
raw_storage_endpoint     = true
disable_sealwrap     = true
disable_printable_check = true

ui = true
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now vault
sudo systemctl status vault
sleep 1
export VAULT_ADDR='http://127.0.0.1:8200'
#export VAULT_ADDR=http://127.0.0.1:8200
echo "export VAULT_ADDR=http://127.0.0.1:8200" >> ~/.bashrc
#sudo rm -rf  /var/lib/vault/data/*
# Wait 30s for Vault to start
(while [[ $count -lt 15 && "$(vault status 2>&1)" =~ "connection refused" ]]; do ((count=count+1)) ; echo "$(date) $count: Waiting for Vault to start..." ; sleep 2; done && [[ $count -lt 15 ]])
[[ $? -ne 0 ]] && echo "ERROR: Error waiting for Vault to start" && exit 1


echo "# Initialize Vault Server"
echo "-------------------------"
vault operator init -recovery-threshold=1 -key-shares=1 -key-threshold=1 > /tmp/vault_unseal_keys.txt
vault_unseal_key=$(cat /tmp/vault_unseal_keys.txt | grep "Unseal Key 1" | sed 's/Unseal Key 1: //')
vault_root_token=$(cat /tmp/vault_unseal_keys.txt | grep "Initial Root Token" | sed 's/Initial Root Token: //')

echo "# Unseal Vault Server"
echo "---------------------"

vault operator unseal "${vault_unseal_key}"
export VAULT_TOKEN="${vault_root_token}"

# Initialize Vault, save encrypted unseal and root keys to Cloud Storage bucket.
if [[ $(vault status) =~ "Sealed: true" ]]; then
  echo "Vault already initialized"
else
#  vault operator init  > /tmp/vault_init.txt

  gcloud kms encrypt \
    --location=global  \
    --keyring=vault-ring \
    --key=vault-key \
    --plaintext-file=/tmp/vault_unseal_keys.txt \
    --ciphertext-file=/tmp/vault_unseal_keys.txt.encrypted

  gsutil cp /tmp/vault_unseal_keys.txt.encrypted gs://vault-storage
  rm -f /tmp/vault_unseal_keys.txt*
fi

echo "# Wait until Vault Server is responsive"
echo "----------------------------------------"
while [ -z "$(curl -s http://127.0.0.1:8200/v1/sys/health)" ]; do
  sleep 3
done

vault status -address http://127.0.0.1:8200/
