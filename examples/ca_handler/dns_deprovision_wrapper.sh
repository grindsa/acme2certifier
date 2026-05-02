#!/bin/bash
# Wrapper script to safely deprovision DNS challenge
# Usage: dns_deprovision_wrapper.sh <acme_sh_script> <dns_update_script> <basename_w_ext> <fqdn> <txt_record_value> [shell]

set -euo pipefail

ACME_SH_SCRIPT="$1"
DNS_UPDATE_SCRIPT="$2"
BASENAME_W_EXT="$3"
FQDN="$4"
TXT_RECORD_VALUE="$5"

# Optionally, a shell can be specified as $6
if [ $# -ge 6 ]; then
    SHELL_EXEC="$6"
else
    SHELL_EXEC="/bin/bash"
fi

# Source scripts and call the remove function
$SHELL_EXEC -c "source \"$ACME_SH_SCRIPT\" &>/dev/null; source \"$DNS_UPDATE_SCRIPT\"; ${BASENAME_W_EXT}_rm \"$FQDN\" \"$TXT_RECORD_VALUE\""
