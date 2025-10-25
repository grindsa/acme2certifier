# Parse JSON Secret Action

A reusable GitHub Action that parses a JSON secret and creates environment variables for each key-value pair.

## Features

- ✅ Parse any JSON structure dynamically
- ✅ Optional variable name prefixes
- ✅ Uppercase/lowercase key conversion
- ✅ JSON validation with error handling
- ✅ Secure handling of sensitive data
- ✅ Detailed outputs for debugging

## Usage

### Basic Usage

```yaml
steps:
  - name: Parse HARICA config
    uses: ./.github/actions/parse-json-secret
    with:
      json_secret: ${{ secrets.HARICA }}
  
  - name: Use the variables
    run: |
      echo "ACME URL: $ACME_URL"
      echo "Domain: $DOMAIN"
      echo "EAB KID: $EAB_KID"
```

### With Prefix

```yaml
steps:
  - name: Parse HARICA config with prefix
    uses: ./.github/actions/parse-json-secret
    with:
      json_secret: ${{ secrets.HARICA }}
      prefix: 'HARICA'
      uppercase: 'true'
  
  - name: Use prefixed variables
    run: |
      echo "HARICA_ACME_URL: $HARICA_ACME_URL"
      echo "HARICA_DOMAIN: $HARICA_DOMAIN"
```

### With Outputs

```yaml
steps:
  - name: Parse config
    id: parse-config
    uses: ./.github/actions/parse-json-secret
    with:
      json_secret: ${{ secrets.HARICA }}
      prefix: 'HARICA'
  
  - name: Show parsing results
    run: |
      echo "Created ${{ steps.parse-config.outputs.variable_count }} variables"
      echo "Variables: ${{ steps.parse-config.outputs.variable_names }}"
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `json_secret` | The JSON secret to parse | Yes | - |
| `prefix` | Optional prefix for environment variable names | No | '' |
| `uppercase` | Convert keys to uppercase | No | 'true' |

## Outputs

| Output | Description |
|--------|-------------|
| `variable_count` | Number of environment variables created |
| `variable_names` | Comma-separated list of variable names created |

## Examples

### Example 1: HARICA CA Configuration

**Secret `HARICA`:**

```json
{
  "acme_url": "https://acme.harica.gr/v2/DV",
  "eab_kid": "your-eab-kid",
  "eab_hmac_key": "your-eab-hmac-key",
  "domain": "example.com"
}
```

**Workflow:**

```yaml
- name: Parse HARICA config
  uses: ./.github/actions/parse-json-secret
  with:
    json_secret: ${{ secrets.HARICA }}

- name: Use HARICA config
  run: |
    echo "ACME Server: $ACME_URL"
    echo "Test Domain: $DOMAIN"
    # EAB_KID and EAB_HMAC_KEY are also available
```

### Example 2: Multiple CA Configurations

```yaml
strategy:
  matrix:
    ca: [harica, letsencrypt, buypass]

steps:
  - name: Parse CA config
    uses: ./.github/actions/parse-json-secret
    with:
      json_secret: ${{ secrets[matrix.ca | upper] }}
      prefix: ${{ matrix.ca | upper }}
      
  - name: Configure CA
    run: |
      # Variables are available with prefix: HARICA_ACME_URL, etc.
      echo "Configuring ${{ matrix.ca }}"
```

## Security Notes

- Sensitive values (like HMAC keys) are not logged
- JSON validation prevents injection attacks
- Environment variables are scoped to the job
- Inputs are handled securely through environment variables

## Error Handling

The action will fail with a clear error message if:

- No JSON secret is provided
- The JSON is invalid or malformed
- Required dependencies (jq) are not available