# Install SPIRE Agents

## Step 1: Obtain the SPIRE Binaries

Pre-built SPIRE releases can be found on the [SPIRE downloads page](https://spiffe.io/downloads/#spire-releases). The tarballs contain both server and agent binaries.

If you wish, you may also [build SPIRE from source](https://github.com/spiffe/spire/blob/main/CONTRIBUTING.md).

## Step 2: Install the Server and Agent

This introductory guide describes how to install the server and agent on the same node. On a typical production deployment you will have the server installed on one node and one or more agents installed on distinct nodes. 

To install the server and agent:

1. Download the tarball for your platform from the [SPIRE releases page](https://github.com/spiffe/spire/releases/latest) and then extract it into the **/opt/spire** directory, substituting `<version>` and `<asset>` for the release version and asset name you downloaded:

    ```console
    wget https://github.com/spiffe/spire/releases/download/<version>/<asset>.tar.gz
    tar zvxf <asset>.tar.gz
    sudo cp -r spire-<version>/. /opt/spire/
    ```

2. Add `spire-server` and `spire-agent` to your $PATH for convenience:

    ```console
    sudo ln -s /opt/spire/bin/spire-server /usr/bin/spire-server
    sudo ln -s /opt/spire/bin/spire-agent /usr/bin/spire-agent
    ```

## Step 3: Configure the Agent

Once the SPIRE Agent has been installed, you need to configure it for your environment. See [Configuring SPIRE](configuring.md) for details about how to configure SPIRE, in particular Node Attestation and Workload Attestation.

Note that the SPIRE Agent must be restarted once its configuration has been modified for changes to take effect.

If you haven't already, see [Install SPIRE Server](install-server.md) to learn how to install the SPIRE Server.

# Installing SPIRE Agents on Kubernetes

> **Warning**
> You must run all commands from the directory containing the **.yaml** files used for configuration. See the [Obtain the Required Files](install-server.md#step-1-obtain-the-required-files) section of the SPIRE Server installation guide for details.

To install SPIRE Agents on Kubernetes, you:

1. Create the agent service account
2. Create the agent configmap
3. Create the agent daemonset

See the following sections for details.

## Step 1: Create Agent Service Account

Apply the **agent-account.yaml** configuration file to create a service account named **spire-agent** in the **spire** namespace:

```console
$ kubectl apply -f agent-account.yaml
```

To allow the agent read access to the kubelet API to perform workload attestation, a ClusterRole must be created that confers the appropriate entitlements to Kubernetes RBAC, and that ClusterRoleBinding must be associated with the service account created in the previous step.

1. Create a ClusterRole named **spire-agent-cluster-role** and a corresponding ClusterRoleBinding by applying the **agent-cluster-role.yaml** configuration file:

    ```console
    $ kubectl apply -f agent-cluster-role.yaml
    ```

2. To confirm successful creation, verify that the ClusterRole appears in the output of the following command:

    ```console
    $ kubectl get clusterroles --namespace spire | grep spire
    ```

## Step 2: Create Agent Configmap

Apply the **agent-configmap.yaml** configuration file to create the agent configmap. This is mounted as the `agent.conf` file that determines the SPIRE Agent's configuration. 

```console
$ kubectl apply -f agent-configmap.yaml
```

The **agent-configmap.yaml** file specifies a number of important directories, notably **/run/spire/sockets** and **/run/spire/config**. These directories are bound in when the agent container is deployed.

Follow the [Configuring SPIRE](configuring.md) section for full details on how to configure the SPIRE Agent, in particular Node Attestation and Workload Attestation.

Note that the a SPIRE Agent must be restarted once its configuration has been modified for changes to take effect.

## Step 3: Create Agent Daemonset

Agents are deployed as a daemonset and one runs on each Kubernetes worker instance.

Deploy the SPIRE agent by applying the **agent-daemonset.yaml** configuration.

```console
$ kubectl apply -f agent-daemonset.yaml
```

This creates a daemonset called **spire-agent** in the **spire** namespace and starts up a **spire-agent** pod along side **spire-server**, as demonstrated in the output of the following two commands:

```console
$ kubectl get daemonset --namespace spire

NAME          DESIRED   CURRENT   READY   UP-TO-DATE   AVAILABLE   NODE SELECTOR   AGE
spire-agent   1         1         1       1            1           <none>          6m45s

$ kubectl get pods --namespace spire

NAME                           READY   STATUS    RESTARTS   AGE
spire-agent-88cpl              1/1     Running   0          6m45s
spire-server-0                 1/1     Running   0          103m
```

When the agent deploys, it binds the volumes summarized in the following table:

| Volume            | Description                                                                                                                                                                    | Mount Location         |
|:------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:-----------------------|
| **spire-config**  | The spire-agent configmap created in the  [Create Agent Configmap](#step-2-create-agent-configmap) step.                                                                       | **/run/spire/config**  |
| **spire-sockets** | The hostPath, which will be shared with all other pods running on the same worker host. It contains a UNIX domain socket that workloads use to communicate with the agent API. | **/run/spire/sockets** |

# Where next?

If you haven't already, see [Install SPIRE Server](install-server.md) to learn how to install the SPIRE Server.

Once you've installed SPIRE Server and Agents, consider reviewing the guide on [Configuring the SPIRE Server and Agents](configuring.md).

