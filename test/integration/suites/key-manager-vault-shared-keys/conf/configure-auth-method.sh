#!/bin/sh

set -e -o pipefail

vault policy write spire /tmp/spire.hcl

vault auth enable kubernetes
vault write auth/kubernetes/config kubernetes_host=https://$KUBERNETES_SERVICE_HOST:$KUBERNETES_SERVICE_PORT_HTTPS
vault write auth/kubernetes/role/my-role \
      bound_service_account_names=spire-server \
      bound_service_account_namespaces=spire \
      token_ttl=1m \
      policies=spire
