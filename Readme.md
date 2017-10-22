# INSTALL
  
On GCE/GKE and AWS, kube-up automatically configures the proper VM size for your master depending on the number of nodes in your cluster. On other providers, you will need to configure it manually. For reference, the sizes we use on GCE are

- 1-5 nodes: n1-standard-1
- 6-10 nodes: n1-standard-2
- 11-100 nodes: n1-standard-4
- 101-250 nodes: n1-standard-8
- 251-500 nodes: n1-standard-16
- more than 500 nodes: n1-standard-32

And the sizes we use on AWS are

- 1-5 nodes: m3.medium
- 6-10 nodes: m3.large
- 11-100 nodes: m3.xlarge
- 101-250 nodes: m3.2xlarge
- 251-500 nodes: c4.4xlarge
- more than 500 nodes: c4.8xlarge

Note that these master node sizes are currently only set at cluster startup time, and are not adjusted if you later scale your cluster up or down (e.g. manually removing or adding nodes, or using a cluster autoscaler).

## CLUSTER ADDONS:
limits on cpu and memory are based on 4-node cluster test. Need to scale up for larger clusters
     - influxes, grafana, kibana, (kubedns,  dnsmasq, sidecar) - need to scale cpu and memory
     - elasticsearch - increase replicas and a little bit of cpu and memory
     - FluentD - increase cpu and memory slightly as this is already a DaemonSet

## INSTALL PARAMS
     NUM_NODES: Number of nodes to create
     ALLOWED_NOTREADY_NODES - Number of nodes to not wait for

## HA CLUSTER:
> It is akin to wearing underwear, pants, a belt, suspenders, another pair of underwear, and another pair of pants 

No kidding this is in the k8s docs
Easiest thing is to add master nodes to a single master cluster. The monitoring flow looks like the following:

	systemd/monit -- (monitors) --> kubelet -- (monitors) --> master processes

If you are using monit, you should also install the monit daemon (apt-get install monit) and the monit-kubelet and monit-docker configs. On systemd systems you `systemctl enable kubelet` and `systemctl enable docker`.

### Reliable Data Storage Layer
- Cluster ETCD:
     - On each master node copy etcd.yaml in /etc/kubernetes/manifests/etcd.yaml
     - Check if all etcd nodes are part of cluster using `etcdctl member list`
     - etcd can have persistent disk too on cloud platforms
     - You can use a clustered FS such as Ceph or Gluster

### Replicate API Server

- Create an empty kube-apiserver.log file
- /srv/kubernetes - copy a bunch of files from existing master 
	- basic_auth.csv - basic auth user and password
	- ca.crt - Certificate Authority cert
	- known_tokens.csv - tokens that entities (e.g. the kubelet) can use to talk to the apiserver
	- kubecfg.crt - Client certificate, public key
	- kubecfg.key - Client certificate, private key
	- server.cert - Server certificate, public key
	- server.key - Server certificate, private key
- Then copy `kube-apiserver.yaml` to `/etc/kubernetes/manifests/` (now 3 api servers are running)
- set up a load balancer using cloud provider
- Configure kubectl and other commands that talk to api server to use load balancer ip

### Use leader election for controller and scheduler
`--leader-elect` flag in controller and scheduler.
	
	touch /var/log/kube-scheduler.log
	touch /var/log/kube-controller-manager.log

### Tell kubelets to talk to LB master
If you have an existing cluster, this is as simple as reconfiguring your kubelets to talk to the load-balanced endpoint, and restarting the kubelets on each node.
If you are turning up a fresh cluster, you will need to install the kubelet and kube-proxy on each worker node, and set the --apiserver flag to your replicated endpoint.

### Get bins from here
[https://github.com/kubernetes/kubernetes/releases](https://github.com/kubernetes/kubernetes/releases)

## KUBEADM INSTALL (TODO)

later

## K8s cluster from scratch (TODO)
[https://kubernetes.io/docs/getting-started-guides/scratch/](https://kubernetes.io/docs/getting-started-guides/scratch/)

# K8s Network Model

With or without overlay network

- Using CNI (container network interface). e.g. calico, flannel, weave, etc
- Using CloudProvider Routes interface (GCE and AWS setup)
- Manual network config

`SERVICE_CLUSTER_IP_RANGE` to select the CIDR range for k8s services. However, service IPs do not necessarily need to be routable. The kube-proxy takes care of translating Service IPs to Pod IPs before traffic leaves the node

### CNI (TODO)
Kubelet needs the following params

- `--network-plugin=cni`
- `--cni-conf-dir`: (default /etc/cni/net.d)
- 

### cloud provider module
[Useful details about cloud provider in a github issue that is looking to remove cloud provider from k8s core](https://github.com/kubernetes/community/blob/master/contributors/design-proposals/cloud-provider-refactoring.md)

Among these controller loops, the following are cloud provider dependent:

- nodeController
- volumeController
- routeController
- serviceController

The nodeController uses the cloudprovider to check if a node has been deleted from the cloud. If cloud provider reports a node as deleted, then this controller immediately deletes the node from kubernetes. This check removes the need to wait for a specific amount of time to conclude that an inactive node is actually dead.

The volumeController uses the cloudprovider to create, delete, attach and detach volumes to nodes. For instance, the logic for provisioning, attaching, and detaching a EBS volume resides in the AWS cloudprovider. The volumeController uses this code to perform its operations.

The routeController configures routes for hosts in the cloud provider.

The serviceController maintains a list of currently active nodes, and is responsible for creating and deleting LoadBalancers in the underlying cloud.

Kubelet also has cloud provider code :

- find instance id, zone etc
- check configmap using cloud nodename
- poll to see if node ip changed, and if yes, mark unschedulable, and update routes, and then mark schedulable

APIserver: 

- transfering ssh keys to nodes
- setting labels for persistent volumes?

## Service Objects
- with selector: endpoints are configured
- without selector: manually add endpoints. Endpoint IPs may not be loopback (127.0.0.0/8), link-local (169.254.0.0/16), or link-local multicast (224.0.0.0/24).

types:

- ClusterIP: If `None` then headless service, generally do not set it. Assigned automatically
- NodePort
- LoadBalancer
- ExternalName: special case for no selector and no ep. alias to another service outside the cluster 
  
  		kind: Service
  		spec:
  			type: ExternalName
  			externalName: service.example.com

### Headless services
No Loadbalancing and no IP

- With selector: No service IP but A records for endpoints are created. 
- Without Selector: A records for endpoints that share the same name as service (manually created EPs)

## Cluster DNS ADDON
- watches api server and creates DNS records
- SRV records created too `_http._tcp.myserv.myns`
  		
## Ingress

(TODO)

## Network Policies



# k8s security model

[https://kubernetes.io/docs/admin/accessing-the-api/](https://kubernetes.io/docs/admin/accessing-the-api/)

	 Authentication    ->    Authorization   ->    Admission Control
	(e.g. passwords)          (e.g. roles)        (API server plugin)

## Users
 - normal users: managed by some 3rd party
 - service accounts: users managed by k8s api, bound to a namespace, creds are stored in secrets and mounted into pods

## kube-apiserver

- `--client-ca-file`: x509 certs, user is /CN=someuser groups using /O=somegroup1/O=somegroup2
- `--token-auth-file`: static tokens , no expiration, file changes requires restart of api server, The token file is a csv file with a minimum of 3 columns: token, user name, user uid, followed by optional group names. Note, if you have more than one group the column must be double quoted. http headers require the following header `Authorization: Bearer TOKEN`
- bootstrap tokens (exp): `--experimental-bootstrap-token-auth`, `--controllers=*,tokencleaner`. Flags are set by kubeadm
- `--basic-auth-file`: The basic auth file is a csv file with a minimum of 3 columns: password, user name, user id. In Kubernetes version 1.6 and later, you can specify an optional fourth column containing comma-separated group names. If you have more than one group, you must enclose the fourth column value in double quotes (“)
- service account tokens: not clear how to use
- oauth2: beyond the scope of this doc
- authenticating proxy: The API server can be configured to identify users from request header values, such as `X-Remote-User`. It is designed for use in combination with an authenticating proxy, which sets the request header value.
	- `--requestheader-username-headers`: Header names to check, in order, for the user identity. The first header containing a value is used as the username.

### Securing CONTROL PLANE

#### APISERVER

Trusted CA

		--client-ca-file string                                   If set, any request presenting a client certificate signed by one of the authorities in the client-ca-file is authenticated with an identity corresponding to the CommonName of the client certificate.

API server talks to kubelet and kubelet talks to APIServer. When kubelet talks to API server this cert,key are used, kubelet should be passed the --client-ca-file used to sign the cert. 

		--kubelet-client-certificate string                       Path to a client cert file for TLS.
		--kubelet-client-key string                               Path to a client key file for TLS.
		--kubelet-https                                           Use https for kubelet connections. (default true)
		
When api server talks to kubelet, then the cert used by kubelet should be signed by the following CA (if private CA)

		--kubelet-certificate-authority string                    Path to a cert file for the certificate authority.

Looks like this is for api server HTTPS communication

		--tls-ca-file string                                      If set, this certificate authority will used for secure access from Admission Controllers. This must be a valid PEM-encoded CA bundle. Alternatively, the certificate authority can be appended to the certificate provided by --tls-cert-file.
      	--tls-cert-file string                                    File containing the default x509 Certificate for HTTPS. (CA cert, if any, concatenated after server cert). If HTTPS serving is enabled, and --tls-cert-file and --tls-private-key-file are not provided, a self-signed certificate and key are generated for the public address and saved to /var/run/kubernetes.
      	--tls-private-key-file string                             File containing the default x509 private key matching --tls-cert-file.
      	--tls-sni-cert-key namedCertKey                           A pair of x509 certificate and private key file paths, optionally suffixed with a list of domain patterns which are fully qualified domain names, possibly with prefixed wildcard segments. If no domain patterns are provided, the names of the certificate are extracted. Non-wildcard matches trump over wildcard matches, explicit domain patterns trump over extracted names. For multiple key/certificate pairs, use the --tls-sni-cert-key multiple times. Examples: "example.crt,example.key" or "foo.crt,foo.key:*.foo.com,foo.com". (default [])


Communication with etcd is secured using

		--etcd-cafile string                                      SSL Certificate Authority file used to secure etcd communication.
   		--etcd-certfile string                                    SSL certification file used to secure etcd communication.
      	--etcd-keyfile string                                     SSL key file used to secure etcd communication.


When API server needs to call out to webhook ADC or do proxy the following are used to validate. Also see --requestheader-client-ca-file

		--proxy-client-cert-file string                           Client certificate used to prove the identity of the aggregator or kube-apiserver when it must call out during a request. This includes proxying requests to a user api-server and calling out to webhook admission plugins. It is expected that this cert includes a signature from the CA in the --requestheader-client-ca-file flag. That CA is published in the 'extension-apiserver-authentication' configmap in the kube-system namespace. Components receiving calls from kube-aggregator should use that CA to perform their half of the mutual TLS verification.
      	--proxy-client-key-file string                            Private key for the client certificate used to prove the identity of the aggregator or kube-apiserver when it must call out during a request. This includes proxying requests to a user api-server and calling out to webhook admission plugins.


Service account key

	--service-account-key-file stringArray     File containing PEM-encoded x509 RSA or ECDSA private or public keys,
	used to verify ServiceAccount tokens. If unspecified, --tls-private-key-file is used. The specified file can
	contain multiple keys, and the flag can be specified multiple times with different files.
  
#### ETCD

[https://coreos.com/etcd/docs/latest/op-guide/security.html](https://coreos.com/etcd/docs/latest/op-guide/security.html)

	--cert-file=/etc/etcd/kubernetes.pem
  	--key-file=/etc/etcd/kubernetes-key.pem
  	--client-cert-auth
  	
  	--trusted-ca-file=/etc/etcd/ca.pem
 	--peer-cert-file=/etc/etcd/kubernetes.pem
  	--peer-key-file=/etc/etcd/kubernetes-key.pem
 	--peer-trusted-ca-file=/etc/etcd/ca.pem
  	--peer-client-cert-auth
  	
  	
#### KUBELET

	--client-ca-file=
	--tls-cert-file=
	--tls-private-key-file=


## kubectl
- `--as=user`: impersonate user
- `--as-group=group`: impersonate group

## Authorization
If more than one authorization modules are configured, Kubernetes checks each module, and if any module authorizes the request, then the request can proceed. If all of the modules deny the request, then the request is denied (HTTP status code 403).

### ABAC:
Set the api server using `--authorization-mode=ABAC --authorization-policy-file=somefile`. The file is one json map per line
- `user/group`: what subject to match
- `apiGroup/namespace/resource`: which api groups such as extensions, namespace such as kube-system, resource such as pods
- non resource path: e.g. `/version` or `/apis`

### webhook: 
This allows the definition of a server that is sent a json object for the request to api server and the server must respond with true/false.

### RBAC
This is a large topic.

- roles, clusterroles
- rolebinding, clusterrolebinding
- privilege escalation
- bootstrapping

### Node authorization

Kubernetes uses a special-purpose authorization mode called Node Authorizer, that specifically authorizes API requests made by Kubelets. In order to be authorized by the Node Authorizer, Kubelets must use a credential that identifies them as being in the system:nodes group, with a username of system:node:<nodeName>. In this section you will create a certificate for each Kubernetes worker node that meets the Node Authorizer requirements.

## Admission Control

Multiple admission controllers can be configured. Each is called in order. Unlike Authentication and Authorization Modules, if any admission controller module rejects, then the request is immediately rejected.


## Cluster Communication

### apiserver to kubelet

By default, the apiserver does not verify the kubelet’s serving certificate, which makes the connection subject to man-in-the-middle attacks, and unsafe to run over untrusted and/or public networks.

`--kubelet-certificate-authority` flag to provide the apiserver with a root certificate bundle to use to verify the kubelet’s serving certificate.

enable secure kubelet [https://kubernetes.io/docs/admin/kubelet-authentication-authorization/](https://kubernetes.io/docs/admin/kubelet-authentication-authorization/)

SSH Tunnels: set up ssh tunnel from master to nodes. no docs on how apiserver does this!!

## Pod Security Policy

[https://kubernetes.io/docs/concepts/policy/pod-security-policy/](https://kubernetes.io/docs/concepts/policy/pod-security-policy/)

Do not fully understand this. 

- Does this require RBAC?
- Looks like it requires securing access to api server even from controller manager

# Scheduling

## nodeSelector:
This is a field in PodSpec. It is a map of KV pairs that needs to match node labels

	kubectl label nodes nodename labelkey=labelvalue
	
## nodeAffinity

nodeSelectorTerms works like `EXPR1` or `EXPR2` where `EXPR1=EXPR1A and EXPR1B`

	spec:
		affinity:
			nodeAffinity:
				requiredDuringSchedulingIgnoredDuringExecution:
					nodeSelectorTerms:
						- matchExpressions:       # EXPR1
							- key: SOMELABELA      # EXPR1A
							  operator: In, NotIn, Exists, DoesNotExist, Gt, Lt
							  values:
							  	- SOMEVALUEA
							  	- SOMEVALUEB
							- key: SOMELABELB      # EXPR1B
							  operator: ...
						- matchExpressions:       # EXPR2
							- key SOMELABELX:
								...
				preferredDuringSchedulingIgnoredDuringExecution:
					- weight: Integer
					  preference:
					  	matchExpressions:
					  		- key:
					  		  ...
					  		- key:
					  		  ...
					- weight: Integer
					  ...
	
The “IgnoredDuringExecution” part of the names means that, similar to how nodeSelector works, if labels on a node change at runtime such that the affinity rules on a pod are no longer met, the pod will still continue to run on the node.

## podAffinity and podAntiAffinity


topologyKey which is the key for the node label that the system uses to denote such a topology domain, 

	spec:
		affinity:
			podAffinity/podAntiAffinity:
				requiredDuringSchedulingIgnoredDuringExecution:
				- labelSelector:
					topologyKey: SOMENODELABELKEY
					matchExpressions:
						- key: PODLABELKEY
						  operator: In, NotIn, Exists, DoesNotExist
						  values:
						  - PODLABELVALUE1
						  - PODLABELVALUE2
						- key: ...

In principle, the topologyKey can be any legal label-key. However, for performance and security reasons, there are some constraints on topologyKey:

1. For affinity and for RequiredDuringScheduling pod anti-affinity, empty topologyKey is not allowed.
2. For RequiredDuringScheduling pod anti-affinity, the admission controller LimitPodHardAntiAffinityTopology was introduced to limit topologyKey to kubernetes.io/hostname. If you want to make it available for custom topologies, you may modify the admission controller, or simply disable it.
3. For PreferredDuringScheduling pod anti-affinity, empty topologyKey is interpreted as “all topologies” (“all topologies” here is now limited to the combination of kubernetes.io/hostname, failure-domain.beta.kubernetes.io/zone and failure-domain.beta.kubernetes.io/region).
4. Except for the above cases, the topologyKey can be any legal label-key.

## Taints and Tolerations

	kubectl taint node <nodename> <key>=<value>:<effect>
	where
		<nodename>  : is name of node
		<key>       : some key
		<value>     : some value
		<effect>    : NoSchedule, PreferNoSchedule, NoExecute
		
		NoSchedule: Pod is not scheduled on this node
		PreferNoSchedule: Soft attempt at no schedule
		NoExecute: Evict if running and do not schedule on this node
		
		<effect>- will remove the effect

Add a toleration to the pod spec. For example to run a node on the master add the following toleration.

operator: Exists (key exists, no value required), Equals (value equals value)

empty key with Exists matches all keys, empty effect matches all effects with key=key

	spec:
		toleration:
		- key: node-role.kubernetes.io/master
		  operator: Exists
		  Effect: NoSchedule
		  
NoExecute with tolerationSeconds means after node is tainted NoExecute, the pod will not be evicted for tolerationSeconds. If no tolerationSeconds then pod is not evicted.

## Memory Resources

A namespace can be defined to use a default memory request and limit if not specified
	
	apiVersion: v1
	kind: LimitRange
	metadata:
  	  name: mem-limit-range
	spec:
  	   limits:
  		- default:
      		memory: 512Mi  # this is the default limit
    	  defaultRequest:
      		memory: 256Mi  # this is the default request
    	  type: Container

## CPU Resources

	spec:
		limits:
		- default:
			cpu: 10m
		  defaultRequest:
		    cpu: 10m
		  type: Container

## Opaque Integer Resources

Add the following to pod.spec.containers[].resources.request.

`pod.alpha.kubernetes.io/opaque-int-resource-{RESNAME}: "1"`

Patch node 

	curl --header "Content-Type: application/json-patch+json" \
	--request PATCH \
	--data '[{"op": "add", "path": "/status/capacity/pod.alpha.kubernetes.io~1opaque-int-resource-{RESNAME}", "value": "4"}]' \
	http://localhost:8001/api/v1/nodes/<your-node-name>/status

## QOS

Used for making scheduling eviction decisions. Need to figure out how?

1. Guaranteed - cpu and memory limit and request are the same
2. Burstable - Not (1) and at least one container has cpu/memory request/limit
3. BestEffort - Not (1) and Not (2)

## Image pull secrets

	apiVersion: v1
	kind: Secret
	metadata:
  		name: myregistrykey
  		namespace: awesomeapps
	data:
  		.dockerconfigjson: BASE64encodeded_.docker.config_file
	type: kubernetes.io/dockerconfigjson

Pod spec is

	spec.imagePullSecrets:
		- name: myregistrykey

## Configmaps

### As env vars

Assume config map is 

	apiVersion: v1
	kind: ConfigMap
	metadata:
  	  name: special-config
  	namespace: default
	data:
  	  SPECIAL_LEVEL: very
  	  SPECIAL_TYPE: charm

Now Pod spec is 

	env:
    - name: SPECIAL_LEVEL_KEY
      valueFrom:
        configMapKeyRef:
          name: special-config
          key: special_level

All keys

	envFrom:
	- configMapRef:
		name: special-config
		
env and envFrom are both possible in Container Spec. env takes precedence for dup keys. key must be a C_IDENTIFIER (`[A-Za-z_][A-Za-z0-9_]*`)

### As volume mount

	containers:
	- name: mycont
	  volumeMounts:
	  - name: vol1
	  	 mountPath: /tmp/myconfig

	volumes:
	- name: vol1
	  configMap:
	  	name: special-config
	  	
Each key will show up as a file in mountPath. When configmap is updated, mounted file is updated as well. 


## Secrets

Similar to configMaps but all data is base64 encoded. Can be loaded as env var or volume 


## Persistent Volumes

[All about persistent volumes](https://kubernetes.io/docs/concepts/storage/persistent-volumes)

