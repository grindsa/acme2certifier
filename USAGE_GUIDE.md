# How to Dismiss Test-Related Security Alerts

This guide explains how to use the automated tools to dismiss code scanning alerts in the `test/` directory.

## Quick Start

### Option 1: Using GitHub Actions (Recommended)

This is the easiest method and requires no local setup.

1. **Navigate to Actions tab** in the GitHub repository
2. **Select "Dismiss Test-Related Security Alerts"** workflow from the left sidebar
3. **Click "Run workflow"** button
4. **Choose dry-run option:**
   - Select `true` to preview what would be dismissed (recommended first run)
   - Select `false` to actually dismiss the alerts
5. **Click "Run workflow"** to execute

The workflow will:
- Fetch all open code scanning alerts
- Identify alerts in the `test/` directory
- Show what will be dismissed (dry-run) or dismiss them (actual run)
- Report the results in the workflow logs

### Option 2: Using the Script Locally

If you prefer to run the script from your local machine:

#### Prerequisites
- GitHub CLI installed (`gh`) OR Python with `requests` library
- Authenticated access to the repository
- Permissions: `security_events: write`

#### Steps

1. **Clone the repository:**
   ```bash
   git clone https://github.com/grindsa/acme2certifier.git
   cd acme2certifier
   ```

2. **Authenticate with GitHub:**
   ```bash
   gh auth login
   ```
   
   OR export a personal access token:
   ```bash
   export GITHUB_TOKEN=ghp_your_token_here
   ```

3. **Install dependencies (if not using gh CLI):**
   ```bash
   pip install requests
   ```

4. **Run the script in dry-run mode:**
   ```bash
   python3 tools/dismiss_test_alerts.py --dry-run
   ```
   
   This will show you what alerts would be dismissed without making changes.

5. **Review the output** and verify the alerts are correct

6. **Run the script to dismiss alerts:**
   ```bash
   python3 tools/dismiss_test_alerts.py
   ```
   
   The script will ask for confirmation before dismissing.
   
   Or use auto-confirm mode:
   ```bash
   python3 tools/dismiss_test_alerts.py --yes
   ```

## What Gets Dismissed?

The script will dismiss alerts with these criteria:

- ✅ **Location**: File path starts with `test/`
- ✅ **State**: Alert is currently "open"
- ✅ **All severities**: Low, Medium, High
- ✅ **All tools**: Bandit, CodeQL, etc.

Each dismissed alert will have:
- **Reason**: `used in tests`
- **Comment**: "This alert is in the test directory and the flagged code is used for testing purposes."

## Example Output

```
Fetching code scanning alerts for grindsa/acme2certifier...
Found 500 open alerts
Found 464 alerts in test/ directory

Alerts to be dismissed:
  #123: B108 (medium) in test/test_helper.py:45
  #124: B303 (medium) in test/test_certificate.py:102
  #125: B108 (medium) in test/test_account.py:234
  #126: SQL001 (high) in test/test_challenge.py:789
  ... (460 more)

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

## Troubleshooting

### "Permission denied" or "403 Forbidden"

**Solution**: Ensure you have the correct permissions:
- Repository collaborator with write access
- `security_events: write` permission
- Valid authentication token

### "Failed to fetch alerts"

**Possible causes**:
1. Network connectivity issues
2. GitHub API rate limiting
3. Authentication problems

**Solutions**:
- Check your internet connection
- Wait and retry (rate limit resets hourly)
- Re-authenticate with GitHub
- Verify your token has correct scopes

### "No test-related alerts to dismiss"

This means one of:
- ✅ All test alerts have already been dismissed (good!)
- ℹ️ No code scanning alerts exist
- ℹ️ All existing alerts are in production code (not test/)

### Script shows network errors in CI

This is expected if running in a restricted environment. Use the GitHub Actions workflow instead, which runs with proper permissions.

## Important Warnings

⚠️ **Review Before Dismissing**: Always run in dry-run mode first to verify which alerts will be dismissed.

⚠️ **Legitimate Security Issues**: Some alerts in tests might indicate actual security problems:
- Hardcoded production credentials accidentally in tests
- Vulnerabilities in test dependencies that could affect CI/CD
- Test code that might be copied to production

⚠️ **Audit Trail**: Dismissed alerts remain in the security log with reason and timestamp. You can always review or re-open them.

## Regular Maintenance

Consider running this script:
- **After major test updates**: When adding new test files
- **Monthly**: As part of regular security review
- **Before security audits**: To clean up the security dashboard

## Manual Alternative

If you prefer to dismiss alerts manually through the GitHub UI:

1. Go to repository **Security** → **Code scanning alerts**
2. Click **Filters** and add: `is:open path:test/`
3. Review the filtered alerts
4. Select alerts to dismiss
5. Click **Dismiss alert** → Choose **Used in tests** as reason
6. Add comment if desired
7. Confirm dismissal

## Support

For issues or questions:
- Check the repository's Issues tab
- Review the workflow logs in Actions tab
- Consult the script's README: `tools/README_dismiss_alerts.md`
