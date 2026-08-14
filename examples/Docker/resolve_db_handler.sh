#!/bin/bash
# Resolve DB handler short name matching acme2certifier.acme_srv.db_handler:
#   [DBhandler] handler_module > handler > ACME_SRV_DB_HANDLER > wsgi
# Prints: wsgi | django

a2c_cfg_dbhandler_value() {
    local cfg="$1"
    local key="$2"
    [[ -f "$cfg" ]] || return 0
    awk -v key="$key" '
        /^\[DBhandler\]/ { insec = 1; next }
        /^\[/ { insec = 0 }
        insec && $0 ~ "^[[:space:]]*" key "[[:space:]]*:" {
            sub("^[[:space:]]*" key "[[:space:]]*:[[:space:]]*", "")
            gsub(/[[:space:]]+$/, "")
            if (length($0) > 0) { print; exit }
        }
    ' "$cfg"
}

a2c_normalize_db_handler() {
    local input="$1"
    local raw
    raw=$(printf '%s' "${input}" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
    case "$raw" in
        ""|wsgi|acme2certifier.dbhandlers.wsgi_handler)
            printf '%s\n' "wsgi"
            ;;
        django|acme2certifier.dbhandlers.django_handler)
            printf '%s\n' "django"
            ;;
        *django_handler*|*django*)
            printf '%s\n' "django"
            ;;
        *wsgi_handler*|*wsgi*)
            printf '%s\n' "wsgi"
            ;;
        *)
            # Custom module: treat as wsgi for bootstrap branching.
            printf '%s\n' "wsgi"
            ;;
    esac
    return 0
}

a2c_resolve_db_handler() {
    local cfg="${1:-/var/www/acme2certifier/volume/acme_srv.cfg}"
    local raw=""
    local handler_module=""
    local handler=""

    handler_module=$(a2c_cfg_dbhandler_value "$cfg" "handler_module")
    handler=$(a2c_cfg_dbhandler_value "$cfg" "handler")

    if [[ -n "$handler_module" ]]; then
        raw="$handler_module"
    elif [[ -n "$handler" ]]; then
        raw="$handler"
    elif [[ -n "${ACME_SRV_DB_HANDLER:-}" ]]; then
        raw="$ACME_SRV_DB_HANDLER"
    else
        raw="wsgi"
    fi

    a2c_normalize_db_handler "$raw"
    return 0
}
