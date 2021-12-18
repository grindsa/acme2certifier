<!-- markdownlint-disable  MD013 -->
<!-- wiki-title Using cert manager to enroll certificate in Kubernetes environments -->
# Using cert-manager to enroll certificate in Kubernetes environments

I don not really have a full kubernets environment. Thus, I was using [https://microk8s.io/](https://microk8s.io/) for testing.

## Prerequisites

- cert-manager must be installed. See [instructions](https://cert-manager.io/docs/installation/kubernetes/) for further information. (I was installing with regular manifest but did change to helm to ensure that I always use the latest version)

## Issuer configuration

The below steps based on instructions taken from [cert-manager documention](https://cert-manager.io/docs/configuration/acme/). Cert-manager can run as `Issuser` or `ClusterIssuer` ressource. The below configuration example uses `Issuer` ressource; an `ClusterIssuer` configuration is part of the [release regression](../.github/k8s-cert-mgr-http-01.yml) testing both `http-01` and `dns-01` challenge validation.

- Create an issuer configuration file as below

```bash
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager-acme
---
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: acme2certifier
  namespace: cert-manager-acme
spec:
  acme:
    email: foo@bar.local
    server: http://192.168.14.1/directory
    privateKeySecretRef:
      # Secret resource that will be used to store the account's private key.
      name: issuer-account-key
    # Add a single challenge solver, HTTP01 using nginx
    solvers:
    - http01:
        ingress:
          class: nginx
---
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: acme-cert
  namespace: cert-manager-acme
spec:
  secretName: k8-acme-secret
  issuerRef:
    name: acme2certifier
  dnsNames:
    - k8-acme.bar.local
  # optional but recommended to avoid reenrollment loops in case of short certificate lifetimes
  renewBefore: 48h
```

- apply the configuration. Certificate enrollment should start immediately

```bash
grindsa@ub-20:~$ microk8s.kubectl apply -f acme2certifier.yaml
```

- the enrollment status can be checked via `microk8s.kubectl describe certificate -n cert-manager-acme`

``` bash
grindsa@ub-20:~$ microk8s.kubectl describe certificate -n cert-manager-acme
Name:         acme-cert
Namespace:    cert-manager-acme
Labels:       <none>
Annotations:  API Version:  cert-manager.io/v1alpha3
Kind:         Certificate
...
Spec:
  Dns Names:
    k8-acme.bar.local
  Issuer Ref:
    Name:       acme2certifier
  Secret Name:  acme2certifier-secret
Status:
  Conditions:
    Last Transition Time:  2020-06-28T07:36:05Z
    Message:               Certificate is up to date and has not expired
    Reason:                Ready
    Status:                True
    Type:                  Ready
  Not After:               2021-06-28T07:35:53Z
Events:
  Type    Reason        Age   From          Message
  ----    ------        ----  ----          -------
  Normal  GeneratedKey  60s   cert-manager  Generated a new private key
  Normal  Requested     60s   cert-manager  Created new CertificateRequest resource "acme-cert-3129588559"
  Normal  Issued        58s   cert-manager  Certificate issued successfully
```

- the certificate details can be checked by using the command `microk8s.kubectl get certificate acme-cert -o yaml -n cert-manager-acme`
- You can check the private key with `microk8s.kubectl get secret acme-cert-key -o yaml -n cert-manager-acme`. You should see a base64 encoded key in the `tls.key` field.
- certificate, issuer and namespace can be deleted with `microk8s.kubectl delete -f acme2certifier.yaml`

# Troubleshooting

There are [extensive troubleshooting guides at the cert-manager website](https://cert-manager.io/docs/faq/acme/).

Below a list of commends I considered as most useful for me:

- `kubectl get order -n <name-space>` - to get the list of orders
- `kubectl describe order -n <name-space> <order>` - to display the details of an order
- `kubectl describe challenge -n <name-space>` - show challenges and provisioning status
