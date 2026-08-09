# -*- coding: utf-8 -*-
"""Global Variables for acme2certifier"""

PARSING_ERR_MSG = "failed to parse"
USER_AGENT = "acme2certifier"

# Returned as enrollment detail when dry-run mode skips certificate issuance.
DRYRUN_ENROLLMENT_SKIPPED_DETAIL = (
    "Dry run mode - enrollment and certificate issuance skipped"
)

# Generic client-visible detail for enrollment failures when CA errors are not forwarded.
ENROLLMENT_FAILED_DETAIL = "enrollment failed"

# Generic client-visible detail for database failures (ACME problem / API error payloads).
DB_ERROR_MSG = "Database error"
