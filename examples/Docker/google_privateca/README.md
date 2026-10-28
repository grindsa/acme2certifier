# Google Private CAS REST mock

Enrollment-faithful mock of [Certificate Authority Service REST](https://cloud.google.com/certificate-authority-service/docs/reference/rest) for acme2certifier development and CI.

API surface (v1 certificates):

- [create / get / list / revoke](https://cloud.google.com/certificate-authority-service/docs/reference/rest/v1/projects.locations.caPools.certificates)

Not a full CAS emulator (no pool/CA admin CRUD beyond `GET certificateAuthorities/{id}`).

## Local (test client, no Docker)

```bash
cd examples/Docker/google_privateca
python3 bootstrap_ca.py --output-dir ./ca
python3 server.py --listen 127.0.0.1:8080 --ca-dir ./ca \
  --project demo --location europe-west1 --pool demo-pool
```

Health: `curl -s http://127.0.0.1:8080/healthz`

Create needs `Authorization: Bearer <anything-non-empty>`.

## Docker Compose

Requires an external Docker network named `acme` (or edit `compose.yaml`).

Host data directory (default `/srv/data/google_privateca`, override with `GOOGLE_PRIVATECA_DATA`) is mounted at `/data`:

| Host path | Container | Purpose |
| --- | --- | --- |
| `…/server-cert.pem` | `/data/server-cert.pem` | Optional HTTPS server certificate |
| `…/server-key.pem` | `/data/server-key.pem` | Optional HTTPS private key |
| `…/ca/` | `/data/ca/` | Issuing PKI (created by entrypoint if missing) |

If both `server-cert.pem` and `server-key.pem` are present, the mock listens with TLS; otherwise plain HTTP.

```bash
sudo mkdir -p /srv/data/google_privateca
# optional TLS:
# sudo cp server-cert.pem server-key.pem /srv/data/google_privateca/
docker network create acme   # if needed
cd examples/Docker/google_privateca
docker compose up --build -d
curl -sk https://127.0.0.1:8080/healthz   # or http:// if no TLS files
```

From another container on network `acme`: `https://google-cas-mock:8080` (or `http://` without TLS).

## Enroll with curl

Defaults match compose (`demo` / `europe-west1` / `demo-pool` / `mock-issuing-ca`). Use `https` + `-k` when TLS files are mounted; otherwise `http` and drop `-k`. Any non-empty Bearer token is accepted.

```bash
BASE='https://127.0.0.1:8080'
PARENT='projects/demo/locations/europe-west1/caPools/demo-pool'
AUTH='Authorization: Bearer test'

# CSR
openssl req -new -newkey rsa:2048 -nodes \
  -keyout /tmp/ee-key.pem -out /tmp/ee.csr \
  -subj '/CN=test.acme'

# CreateCertificate
curl -sk -X POST \
  -H "$AUTH" -H 'Content-Type: application/json' \
  --data-binary @<(python3 -c 'import json; print(json.dumps({"pemCsr": open("/tmp/ee.csr").read(), "lifetime": "3600s"}))') \
  "$BASE/v1/${PARENT}/certificates?certificateId=demo1&issuingCertificateAuthorityId=mock-issuing-ca" \
  | tee /tmp/gcas-create.json

# Write leaf + chain PEMs from the response
python3 - <<'PY'
import json
doc = json.load(open("/tmp/gcas-create.json"))
open("/tmp/ee-cert.pem", "w").write(doc["pemCertificate"])
open("/tmp/ee-chain.pem", "w").write("".join(doc["pemCertificateChain"]))
print("name:", doc["name"])
print("serial:", doc["certificateDescription"]["subjectDescription"]["serialNumber"])
PY
```

Get / list-by-serial / revoke:

```bash
NAME="$(python3 -c 'import json; print(json.load(open("/tmp/gcas-create.json"))["name"])')"
SERIAL="$(python3 -c 'import json; print(json.load(open("/tmp/gcas-create.json"))["certificateDescription"]["subjectDescription"]["serialNumber"])')"

curl -sk -H "$AUTH" "$BASE/v1/${NAME}"

curl -sk -H "$AUTH" \
  "$BASE/v1/${PARENT}/certificates?filter=serial_number=\"${SERIAL}\""

curl -sk -X POST -H "$AUTH" -H 'Content-Type: application/json' \
  -d '{"reason":"KEY_COMPROMISE"}' \
  "$BASE/v1/${NAME}:revoke"
```

Handler documentation (config, **service account JSON / `sa.json`**, TLS, Private CAS vs Public CA): [`docs/google_cas.md`](../../../docs/google_cas.md).

## Manual auth check (`check_auth.py`)

One-off (not CI): exercise `google-auth` / Bearer resolution against this mock or real Private CAS. Use a disposable venv — do not install into the project `.venv`:

```bash
d=$(mktemp -d)
python3 -m venv "$d"
"$d/bin/pip" install 'google-auth' requests
# optional: export GOOGLE_APPLICATION_CREDENTIALS=/path/sa.json
"$d/bin/python" check_auth.py --endpoint-url http://127.0.0.1:8080 \
  --project demo --location europe-west1 --pool demo-pool
rm -rf "$d"
```

## CI

Composite action: [`.github/actions/wf_specific/google_cas_ca_handler/mock_prep`](../../../.github/actions/wf_specific/google_cas_ca_handler/mock_prep/action.yml). Exports:

- `GOOGLE_CAS_ENDPOINT_URL=http://google-cas-mock:8080`
- `GOOGLE_CAS_CA_POOL=projects/.../locations/.../caPools/...`
- `GOOGLE_CAS_PROJECT` / `LOCATION` / `POOL` / `ISSUING_CA_ID`
