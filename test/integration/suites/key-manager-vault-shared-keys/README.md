# KeyManager HashiCorp Vault shared key pool suite

## Description

This suite sets up a Kubernetes cluster using [Kind](https://kind.sigs.k8s.io),
installs HashiCorp Vault and Postgres, and runs two SPIRE server replicas that
share the datastore and Vault key identifier with `ca_key_slots = 1`. It then
asserts the following:

* Both replicas are assigned to the same pool slot
* Both replicas report the same active X509 and JWT authorities
* Only one X509 CA and one JWT signing key exist in Vault and in the bundle
* An X509 CA prepared and activated through one replica is synced by the
  other, no extra keys are created, and both replicas can still sign
