#!/usr/bin/env bash
# Patch a live docker-xipki stack (XiPKI 6.3.0 REST gateway) so empty ACME CSR
# subjects become CN=<first DNS SAN>, and drop the acme-issued.invalid profile CN.
#
# Usage (on the XiPKI host):
#   STACK_DIR=/srv/stacks/xipki DATA_DIR=/srv/data/xipki \
#     ./.github/scripts/patch_xipki_cn_from_san.sh
#
# Set SKIP_COMPOSE_UP=1 when the caller rebuilds the stack itself (e.g. xipki_prep).
set -euo pipefail

STACK_DIR="${STACK_DIR:-/srv/stacks/xipki}"
DATA_DIR="${DATA_DIR:-/srv/data/xipki}"
SKIP_COMPOSE_UP="${SKIP_COMPOSE_UP:-0}"
WAR="${STACK_DIR}/xipki-gateway/webapps/rest.war"
GW_LIB="${STACK_DIR}/xipki-gateway/lib"

if [[ ! -f "${WAR}" ]]; then
  echo "rest.war not found at ${WAR}" >&2
  exit 1
fi

export STACK_DIR DATA_DIR

echo "==> Patching tls certprofile (remove acme-issued.invalid)"
python3 - <<'PY'
import json
import os
from pathlib import Path

data_dir = os.environ["DATA_DIR"]
stack_dir = os.environ["STACK_DIR"]
paths = [
    Path(stack_dir) / "xipki-mgmt-cli/xipki/ca-setup/certprofile/certprofile-tls.json",
    Path(data_dir) / "mgmt-cli/xipki/ca-setup/certprofile/certprofile-tls.json",
]
for p in paths:
    if not p.is_file():
        print(f"skip missing {p}")
        continue
    data = json.loads(p.read_text())
    for rdn in data.get("subject", {}).get("rdns", []):
        desc = (rdn.get("type") or {}).get("description")
        if desc in ("c", "o", "ou", "serialNumber", "cn"):
            rdn["minOccurs"] = 0
        if desc == "cn":
            rdn["maxOccurs"] = 1
            rdn.pop("regex", None)
            rdn.pop("value", None)
    for ext in data.get("extensions", []):
        t = ext.get("type") or {}
        if t.get("description") == "subjectAlternativeName" or t.get("oid") == "2.5.29.17":
            ext["critical"] = True
            ext["required"] = True
            ext["inRequest"] = "required"
    p.write_text(json.dumps(data, indent=2) + "\n")
    print(f"updated {p}")
PY

echo "==> Patching RestResponder in ${WAR}"
PATCH_DIR="$(mktemp -d)"
trap 'rm -rf "${PATCH_DIR}"' EXIT

unzip -q -d "${PATCH_DIR}/war" "${WAR}"
mkdir -p "${PATCH_DIR}/extra-lib"
cp -a "${GW_LIB}"/*.jar "${PATCH_DIR}/extra-lib/" 2>/dev/null || true

# Refuse a redirect onto clear text (shell:S6506).
curl --proto '=https' --proto-redir '=https' -fsSL \
  -o "${PATCH_DIR}/RestResponder.java" \
  "https://raw.githubusercontent.com/xipki/xipki/v6.3.0/ca-gateway/rest-gateway/src/main/java/org/xipki/ca/gateway/rest/RestResponder.java"

python3 - "${PATCH_DIR}/RestResponder.java" <<'PY'
import sys
from pathlib import Path

path = Path(sys.argv[1])
text = path.read_text()

imports = (
    "import org.bouncycastle.asn1.ASN1IA5String;\n"
    "import org.bouncycastle.asn1.x500.style.BCStyle;\n"
    "import org.bouncycastle.asn1.x509.Extension;\n"
    "import org.bouncycastle.asn1.x509.GeneralName;\n"
    "import org.bouncycastle.asn1.x509.GeneralNames;\n"
)
if "import org.bouncycastle.asn1.x500.style.BCStyle;" not in text:
    text = text.replace(
        "import org.bouncycastle.asn1.x509.Extensions;\n",
        "import org.bouncycastle.asn1.x509.Extensions;\n" + imports,
    )

needle = (
    "      subject = certTemp.getSubject();\n"
    "      subjectPublicKeyInfo = certTemp.getSubjectPublicKeyInfo();\n"
    "      extensions = X509Util.getExtensions(certTemp);\n"
    "    }\n"
)
replacement = (
    "      subject = certTemp.getSubject();\n"
    "      subjectPublicKeyInfo = certTemp.getSubjectPublicKeyInfo();\n"
    "      extensions = X509Util.getExtensions(certTemp);\n"
    "      // Mirror XiPKI ACME: empty CSR subject -> CN=<first DNS SAN>\n"
    "      subject = subjectWithCnFromSanIfMissing(subject, extensions);\n"
    "    }\n"
)
if "subject = subjectWithCnFromSanIfMissing(subject, extensions);" not in text:
    if needle not in text:
        raise SystemExit("enroll-cert subject extraction block not found")
    text = text.replace(needle, replacement, 1)

helper = """
  private static X500Name subjectWithCnFromSanIfMissing(X500Name subject, Extensions extensions) {
    if (subject != null && subject.getRDNs(BCStyle.CN).length > 0) {
      return subject;
    }
    if (extensions == null) {
      return subject;
    }
    Extension sanExt = extensions.getExtension(Extension.subjectAlternativeName);
    if (sanExt == null) {
      return subject;
    }
    GeneralNames gns = GeneralNames.getInstance(sanExt.getParsedValue());
    for (GeneralName gn : gns.getNames()) {
      if (gn.getTagNo() == GeneralName.dNSName) {
        String dns = ASN1IA5String.getInstance(gn.getName()).getString();
        if (dns != null && !dns.isEmpty()) {
          return new X500Name("CN=" + dns);
        }
      }
    }
    return subject;
  }

"""
if "private static X500Name subjectWithCnFromSanIfMissing" not in text:
    idx = text.rfind("\n}")
    if idx < 0:
        raise SystemExit("could not find class end")
    text = text[:idx] + "\n" + helper + text[idx:]

path.write_text(text)
print(f"patched {path}")
PY

mkdir -p "${PATCH_DIR}/build"
docker run --rm \
  -u "$(id -u):$(id -g)" \
  -v "${PATCH_DIR}:/work" \
  -w /work \
  eclipse-temurin:17-jdk \
  bash -lc '
    set -euo pipefail
    CP=$(find war/WEB-INF/lib extra-lib -name "*.jar" 2>/dev/null | tr "\n" ":")
    CP="${CP}war/WEB-INF/classes"
    javac -encoding UTF-8 -cp "$CP" -d build RestResponder.java
    cp -f build/org/xipki/ca/gateway/rest/RestResponder*.class \
      war/WEB-INF/classes/org/xipki/ca/gateway/rest/
    jar cf rest.war -C war .
  '

cp -f "${WAR}" "${WAR}.bak.$(date +%Y%m%d%H%M%S)"
cp -f "${PATCH_DIR}/rest.war" "${WAR}"
echo "Wrote ${WAR}"

if [[ "${SKIP_COMPOSE_UP}" == "1" ]]; then
  echo "==> Skipping gateway recreate (SKIP_COMPOSE_UP=1)"
else
  echo "==> Rebuild/restart gateway"
  cd "${STACK_DIR}"
  docker compose up -d --build --force-recreate --no-deps xipki-gateway
fi
echo "Done."
