# Listener Configuration Files

This directory contains example YAOTL configuration files for quickly loading listener settings into the Havoc client GUI. These use the **same format as teamserver profiles** for consistency.

## Usage

1. Open Havoc client
2. Go to **Listeners** → **Add New**
3. Click the **"Load Config"** button
4. Select one of the `.yaotl` files from this directory
5. All fields will be automatically populated
6. Modify as needed and click **Save**

## File Format

These configs use **YAOTL** (Yet Another Obvious Tactical Language) - the same format the Havoc teamserver uses for profiles. This maintains consistency across your infrastructure.

## Supported Listener Types

### HTTP/HTTPS Listeners

Example structure:
```yaotl
Listeners {
    Http {
        Name         = "Production HTTPS"
        Hosts        = ["api.example.com", "cdn.example.com"]
        HostBind     = "0.0.0.0"
        HostRotation = "round-robin"
        PortBind     = 443
        PortConn     = 443
        Secure       = true
        UserAgent    = "Mozilla/5.0 ..."

        Uris = [
            "/api/v1/status",
            "/api/v1/health"
        ]

        Headers = [
            "X-Forwarded-For: {HEADER_X_FORWARDED_FOR}",
            "Accept: application/json"
        ]

        Response {
            Headers = [
                "Content-Type: application/json",
                "Server: cloudflare"
            ]
        }
    }
}
```

**Fields:**
- `Name`: Listener display name
- `Hosts`: Array of callback domains/IPs
- `HostBind`: IP to bind server to (usually `"0.0.0.0"`)
- `HostRotation`: `"round-robin"` or `"random"`
- `PortBind`: Port for teamserver to listen on
- `PortConn`: Port agents connect to (can differ if using redirectors)
- `Secure`: `true` for HTTPS, `false` for HTTP
- `UserAgent`: User-Agent string for agent callbacks
- `Uris`: Array of callback URI paths
- `Headers`: Array of custom HTTP headers
- `Response { Headers }`: Optional response headers block

### SMB Listeners

Example structure:
```yaotl
Listeners {
    Smb {
        Name     = "SMB Pivot"
        PipeName = "\\msagent_44"
    }
}
```

**Fields:**
- `Name`: Listener display name
- `PipeName`: Named pipe path (e.g., `"\\msagent_44"`)

### External C2 Listeners

Example structure:
```yaotl
Listeners {
    External {
        Name     = "External C2"
        Endpoint = "external-c2"
    }
}
```

**Fields:**
- `Name`: Listener display name
- `Endpoint`: API endpoint path

## Example Configs

### 1. HTTPS with CloudFlare Headers
File: `https_production.yaotl`

Simulates legitimate CloudFlare-fronted API traffic with proper headers and response characteristics.

### 2. Simple HTTP Dev Listener
File: `http_dev.yaotl`

Basic HTTP listener for lab/dev environments.

### 3. SMB Pivot
File: `smb_pivot.yaotl`

Named pipe listener for SMB-based pivoting through compromised hosts.

### 4. External C2
File: `external_c2.yaotl`

External C2 integration endpoint.

## OPSEC Considerations

**WHY use YAOTL format?**
- **Consistency**: Same format as teamserver profiles - operators don't need to learn multiple syntaxes
- **Portability**: Can extract listener blocks from full profiles and load directly
- **Version control**: YAOTL files are git-friendly and human-readable
- **Profile reuse**: Test listeners in client, then copy to full profile for production

**MEMORY:**
- Config files are parsed once and discarded
- No sensitive data persists after dialog close
- Parser uses regex-based extraction (simple, no heavy libraries)

**VALID:**
- Parser validates YAOTL structure before populating
- Invalid configs show error message without crashing
- Missing optional fields are skipped gracefully
- Supports both single and multi-listener files (loads first listener found)

## Creating Custom Configs

### Option 1: Extract from Full Profile
1. Use an existing teamserver profile (e.g., `profiles/microsoft_teams.yaotl`)
2. Copy just the `Listeners { ... }` block
3. Save as new `.yaotl` file
4. Load in client GUI

### Option 2: Create from Scratch
1. Copy one of the examples
2. Modify fields for your infrastructure
3. Save with descriptive name
4. Test by loading in GUI before deploying to production

## Advanced Usage

### Loading Full Teamserver Profiles

The parser can load **full teamserver profiles** - it will extract just the first listener defined:

```bash
# This works:
./havoc client  # Load Config → profiles/microsoft_teams.yaotl
```

The parser ignores `Teamserver`, `Operators`, `Demon`, and `Service` blocks - only `Listeners` is parsed.

### Multiple Listeners in One File

If a file contains multiple listeners (Http, Smb, External), the parser loads the **first one found** in this priority:
1. Http (including HTTPS via `Secure = true`)
2. Smb
3. External

## Comparison to Teamserver Usage

### Teamserver (server-side):
```bash
./havoc server --profile profiles/microsoft_teams.yaotl
# Loads ALL listeners from profile automatically
```

### Client (GUI):
```
Listeners → Add New → Load Config → Select .yaotl file
# Loads ONE listener at a time, allows modification before saving
```

This workflow allows you to:
- **Test** listener configs in the GUI before production
- **Modify** settings without editing the profile file
- **Quick deploy** known-good configs from your profile library

## Security Notes

- **Never hardcode real IPs/domains in version-controlled configs**
- Use placeholders (e.g., `api.example.com`) and replace before operations
- Store operational configs in encrypted locations
- Consider using separate configs for dev/staging/prod
- Profile files may contain sensitive infrastructure details - treat accordingly

## File Structure

```
listener_configs/
├── README.md                     # This file
├── https_production.yaotl       # HTTPS with CloudFlare mimicry
├── http_dev.yaotl               # Simple HTTP for lab use
├── smb_pivot.yaotl              # SMB named pipe listener
└── external_c2.yaotl            # External C2 endpoint
```

## Troubleshooting

**"No Listeners block found"**
- Ensure file contains `Listeners { ... }` block
- Check for syntax errors (missing braces, quotes)

**"No valid listener type found"**
- Verify listener type is `Http`, `Smb`, or `External` (case-sensitive)
- Check that listener block has opening `{` and closing `}`

**Fields not populating**
- Ensure values are properly quoted (strings in `"quotes"`)
- Arrays must use `[ "item1", "item2" ]` syntax
- Numbers don't need quotes: `PortBind = 443` ✅ not `"443"` ❌

## Future Enhancements

- Export listener config from running listener (reverse operation)
- Support for multiple listener selection/loading
- Profile validation before import
- Listener template library with common C2 profiles
