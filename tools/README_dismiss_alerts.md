# Dismissing Test-Related Code Scanning Alerts

This directory contains a script to automatically dismiss code scanning alerts that are located in the `test/` directory.

## Background

Security scanning tools like Bandit and CodeQL often flag potential security issues in test code. These alerts are typically acceptable in test environments because:

1. Test code uses insecure patterns intentionally to test error handling
2. Test data includes hardcoded credentials or sensitive information for testing purposes
3. Tests may use deprecated or insecure methods to ensure backward compatibility

## The Script

### dismiss_test_alerts.py

This script automatically identifies and dismisses code scanning alerts that are located in the `test/` directory.

**Features:**
- Fetches all open code scanning alerts from GitHub
- Filters alerts that are in the `test/` directory
- Dismisses them with the reason "used in tests"
- Supports both GitHub CLI and direct API access
- Provides dry-run mode to preview changes

**Usage:**

```bash
# Dry-run mode (shows what would be dismissed without making changes)
python3 tools/dismiss_test_alerts.py --dry-run

# Interactive mode (asks for confirmation before dismissing)
python3 tools/dismiss_test_alerts.py

# Auto-confirm mode (dismisses without asking)
python3 tools/dismiss_test_alerts.py --yes
```

**Requirements:**
- GitHub CLI (`gh`) installed and authenticated, OR
- Python `requests` library installed and `GITHUB_TOKEN` environment variable set
- Appropriate permissions to manage code scanning alerts

**Permissions Required:**
- `security_events: write` permission
- Repository access

## Running the Script

### Option 1: Using GitHub Actions (Recommended)

Create a workflow file (`.github/workflows/dismiss-test-alerts.yml`):

```yaml
name: Dismiss Test Alerts

on:
  workflow_dispatch:  # Manual trigger
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday

jobs:
  dismiss-alerts:
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      contents: read
    
    steps:
      - uses: actions/checkout@v4
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.x'
      
      - name: Install dependencies
        run: pip install requests
      
      - name: Dismiss test alerts
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: python3 tools/dismiss_test_alerts.py --yes
```

### Option 2: Using GitHub CLI Locally

```bash
# Authenticate with GitHub
gh auth login

# Run the script
python3 tools/dismiss_test_alerts.py --dry-run
python3 tools/dismiss_test_alerts.py
```

### Option 3: Using Personal Access Token

```bash
# Create a token with security_events:write permission at:
# https://github.com/settings/tokens/new

# Export the token
export GITHUB_TOKEN=ghp_your_token_here

# Install requests
pip install requests

# Run the script
python3 tools/dismiss_test_alerts.py --dry-run
python3 tools/dismiss_test_alerts.py
```

## What Gets Dismissed

The script dismisses alerts with the following criteria:

1. **Location**: Alert must be in a file under the `test/` directory
2. **State**: Alert must be in "open" state
3. **Reason**: All matching alerts are dismissed with reason "used in tests"
4. **Comment**: A comment is added: "This alert is in the test directory and the flagged code is used for testing purposes."

## Example Output

```
Fetching code scanning alerts for grindsa/acme2certifier...
Found 500 open alerts
Found 464 alerts in test/ directory

Alerts to be dismissed:
  #123: B108 (medium) in test/test_helper.py:45
  #124: B303 (medium) in test/test_certificate.py:102
  #125: B108 (medium) in test/test_account.py:234
  ...

Dismiss 464 alerts? (yes/no): yes

Dismissing alert #123 (B108 in test/test_helper.py)...
  ✓ Dismissed
Dismissing alert #124 (B303 in test/test_certificate.py)...
  ✓ Dismissed
...

Summary:
  Dismissed: 464
  Failed: 0
```

## Alternative: Manual Process

If you prefer to dismiss alerts manually:

1. Go to the repository's Security tab
2. Click on "Code scanning alerts"
3. Filter by path using: `path:test/`
4. Select alerts to dismiss
5. Click "Dismiss alert" and select "Used in tests" as the reason

## Important Notes

- **Legitimate Issues**: Before dismissing, verify that the alerts are indeed false positives for test code
- **Production Code**: Never dismiss security alerts in production code without proper review
- **Regular Review**: Periodically review dismissed alerts to ensure they remain valid
- **Documentation**: Keep track of why specific patterns are used in tests

## Troubleshooting

### Permission Denied
- Ensure you have `security_events: write` permission
- Check that your token has the correct scopes

### Network Errors
- Verify you can access `api.github.com`
- Check if you're behind a proxy or firewall

### No Alerts Found
- Verify that code scanning is enabled for the repository
- Check that there are open alerts in the Security tab
