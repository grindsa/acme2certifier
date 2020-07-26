<!-- markdownlint-disable  MD013 -->
# Using cert-manager to enroll certificate in Kubernetes environments

I don not really have a full kubernets environment. Thus, I was using [https://microk8s.io/](https://microk8s.io/) for testing.

## Prerequisites

- cert-manager must be installed. See [instructions](https://cert-manager.io/docs/installation/kubernetes/) for further information. (I was installing with regular manifest)

## Issuer configuration

The below steps based on instructions taken from [cert-manager documention](https://cert-manager.io/docs/configuration/acme/)

- Create an issuer configuration file as below

```bash
grindsa@ub-20:~$ cat acme2certifier.yaml
apiVersion: v1
kind: Namespace
metadata:
  name: cert-manager-acme
---
apiVersion: cert-manager.io/v1alpha2
kind: Issuer
metadata:
  name: acme2certifier
  namespace: cert-manager-acme
spec:
  acme:
    email: foo@bar.local
    server: <acme2certifier address>
    privateKeySecretRef:
      # Secret resource that will be used to store the account's private key.
      name: acme-cert
    # Add a single challenge solver, HTTP01 using nginx
    solvers:
    - http01:
        ingress:
          class: nginx
---
apiVersion: cert-manager.io/v1alpha2
kind: Certificate
metadata:
  name: acme-cert
  namespace: cert-manager-acme
spec:
  dnsNames:
    - k8-acme.bar.local.com
  secretName: acme2certifier-secret
  issuerRef:
    name: acme2certifier
```

- apply the configuration. Certificate enrollment shoud start immedeately
```grindsa@ub-20:~$ microk8s.kubectl apply -f acme2certifier.yaml```

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
