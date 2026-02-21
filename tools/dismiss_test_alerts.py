#!/usr/bin/env python3
"""
Script to dismiss code scanning alerts that are located in the test/ directory.
These alerts are typically related to unit testing and can be safely dismissed.

Usage:
    # Dry-run mode (shows what would be dismissed):
    python3 dismiss_test_alerts.py --dry-run
    
    # Interactive mode (asks for confirmation):
    python3 dismiss_test_alerts.py
    
    # Auto-confirm mode (dismisses without asking):
    python3 dismiss_test_alerts.py --yes
"""

import os
import sys
import json
import subprocess

def get_code_scanning_alerts_gh_cli(owner, repo, state='open'):
    """
    Fetch code scanning alerts using GitHub CLI
    
    Args:
        owner: Repository owner
        repo: Repository name
        state: Alert state (open, closed, dismissed, fixed)
    
    Returns:
        List of alerts
    """
    try:
        cmd = [
            'gh', 'api',
            f'repos/{owner}/{repo}/code-scanning/alerts',
            '-X', 'GET',
            '-F', f'state={state}',
            '-F', 'per_page=100'
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        alerts = json.loads(result.stdout)
        return alerts
    except subprocess.CalledProcessError as e:
        print(f"Error running gh CLI: {e}")
        print(f"stderr: {e.stderr}")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None


def get_code_scanning_alerts(owner, repo, token, state='open'):
    """
    Fetch code scanning alerts from GitHub API
    
    Args:
        owner: Repository owner
        repo: Repository name
        token: GitHub token
        state: Alert state (open, closed, dismissed, fixed)
    
    Returns:
        List of alerts
    """
    # Try using gh CLI first
    print("Attempting to fetch alerts using GitHub CLI...")
    alerts = get_code_scanning_alerts_gh_cli(owner, repo, state)
    if alerts is not None:
        return alerts
    
    # Fall back to requests
    print("Falling back to GitHub API via requests...")
    try:
        import requests
        
        url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts"
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        params = {
            'state': state,
            'per_page': 100
        }
        
        all_alerts = []
        page = 1
        
        while True:
            params['page'] = page
            response = requests.get(url, headers=headers, params=params)
            
            if response.status_code != 200:
                print(f"Error fetching alerts: {response.status_code}")
                print(f"Response: {response.text}")
                return None
            
            alerts = response.json()
            if not alerts:
                break
            
            all_alerts.extend(alerts)
            page += 1
        
        return all_alerts
    except ImportError:
        print("Error: requests library not available")
        return None
    except Exception as e:
        print(f"Error: {e}")
        return None


def dismiss_alert(owner, repo, token, alert_number, dismissed_reason, dismissed_comment=None):
    """
    Dismiss a code scanning alert
    
    Args:
        owner: Repository owner
        repo: Repository name
        token: GitHub token
        alert_number: Alert number to dismiss
        dismissed_reason: Reason for dismissal (e.g., 'used in tests', 'false positive')
        dismissed_comment: Optional comment
    
    Returns:
        True if successful, False otherwise
    """
    # Try using gh CLI first
    try:
        cmd = [
            'gh', 'api',
            f'repos/{owner}/{repo}/code-scanning/alerts/{alert_number}',
            '-X', 'PATCH',
            '-F', 'state=dismissed',
            '-F', f'dismissed_reason={dismissed_reason}'
        ]
        
        if dismissed_comment:
            cmd.extend(['-F', f'dismissed_comment={dismissed_comment}'])
        
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        return True
    except subprocess.CalledProcessError as e:
        # gh CLI failed, fall back to requests library
        print(f"  Error with gh CLI: {e.stderr}")
        print(f"  Attempting fallback to requests library...")
    
    # Fall back to requests
    try:
        import requests
        
        url = f"https://api.github.com/repos/{owner}/{repo}/code-scanning/alerts/{alert_number}"
        headers = {
            'Authorization': f'token {token}',
            'Accept': 'application/vnd.github.v3+json'
        }
        
        data = {
            'state': 'dismissed',
            'dismissed_reason': dismissed_reason
        }
        
        if dismissed_comment:
            data['dismissed_comment'] = dismissed_comment
        
        response = requests.patch(url, headers=headers, json=data)
        
        if response.status_code == 200:
            return True
        else:
            print(f"  Error dismissing alert {alert_number}: {response.status_code}")
            print(f"  Response: {response.text}")
            return False
    except Exception as e:
        print(f"  Error: {e}")
        return False


def main():
    # Get parameters from environment or arguments
    owner = os.environ.get('GITHUB_REPOSITORY_OWNER', 'grindsa')
    repo_full = os.environ.get('GITHUB_REPOSITORY', 'grindsa/acme2certifier')
    repo = repo_full.split('/')[-1] if '/' in repo_full else 'acme2certifier'
    token = os.environ.get('GITHUB_TOKEN', '')
    
    # Check for arguments
    dry_run = '--dry-run' in sys.argv
    auto_yes = '--yes' in sys.argv
    
    print(f"Fetching code scanning alerts for {owner}/{repo}...")
    alerts = get_code_scanning_alerts(owner, repo, token, state='open')
    
    if alerts is None:
        print("Failed to fetch alerts")
        print("\nNote: If you're seeing network errors, you may need to run this script")
        print("from an environment with access to the GitHub API, or ensure you have")
        print("the appropriate permissions.")
        sys.exit(1)
    
    print(f"Found {len(alerts)} open alerts")
    
    # Filter alerts that are in the test/ directory
    test_alerts = []
    for alert in alerts:
        location = alert.get('most_recent_instance', {}).get('location')
        if location:
            path = location.get('path', '')
            if path.startswith('test/'):
                test_alerts.append(alert)
    
    print(f"Found {len(test_alerts)} alerts in test/ directory")
    
    if not test_alerts:
        print("No test-related alerts to dismiss")
        return
    
    # Display alerts to be dismissed
    print("\nAlerts to be dismissed:")
    for alert in test_alerts:
        alert_num = alert['number']
        rule_id = alert['rule']['id']
        severity = alert['rule'].get('severity', 'unknown')
        path = alert['most_recent_instance']['location']['path']
        line = alert['most_recent_instance']['location'].get('start_line', '?')
        print(f"  #{alert_num}: {rule_id} ({severity}) in {path}:{line}")
    
    # Dry-run mode
    if dry_run:
        print("\nDry-run mode: no alerts will be dismissed")
        return
    
    # Ask for confirmation unless auto-yes
    if not auto_yes:
        response = input(f"\nDismiss {len(test_alerts)} alerts? (yes/no): ")
        if response.lower() != 'yes':
            print("Cancelled")
            return
    
    # Dismiss the alerts
    dismissed_count = 0
    failed_count = 0
    
    for alert in test_alerts:
        alert_num = alert['number']
        rule_id = alert['rule']['id']
        path = alert['most_recent_instance']['location']['path']
        
        print(f"Dismissing alert #{alert_num} ({rule_id} in {path})...")
        
        if dismiss_alert(owner, repo, token, alert_num, 'used in tests', 
                        'This alert is in the test directory and the flagged code is used for testing purposes.'):
            dismissed_count += 1
            print(f"  ✓ Dismissed")
        else:
            failed_count += 1
            print(f"  ✗ Failed")
    
    print(f"\nSummary:")
    print(f"  Dismissed: {dismissed_count}")
    print(f"  Failed: {failed_count}")


if __name__ == '__main__':
    main()
