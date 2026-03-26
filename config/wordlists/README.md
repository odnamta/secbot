# Wordlists for SecBot Discovery Modules

This directory holds external wordlist files used by the discovery and enumeration modules.
The `.txt` files are **gitignored** because they are large and should be downloaded separately.

## Expected Files

| File | Size | Used By | Source |
|------|------|---------|--------|
| `paths-common.txt` | ~4,750 lines | Content discovery (`content-discovery.ts`) | [SecLists](https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content) |
| `paths-large.txt` | ~37,000 lines | Content discovery (deep mode) | SecLists `raft-large-directories.txt` |
| `params-large.txt` | ~25,000 lines | Param discovery (`param-discovery.ts`) | [Arjun](https://github.com/s0md3v/Arjun) / SecLists |
| `params-burp.txt` | ~6,400 lines | Param discovery (fallback) | Burp Suite built-in wordlist |
| `subdomains-5000.txt` | ~5,000 lines | Subdomain enumeration (`subdomain.ts`) | SecLists `subdomains-top1million-5000.txt` |
| `api-endpoints.txt` | ~285 lines | API endpoint discovery | Curated |

## How to Download

### Option 1: From SecLists (recommended)

```bash
# Clone SecLists (or download specific files)
git clone --depth 1 https://github.com/danielmiessler/SecLists.git /tmp/SecLists

# Copy what you need
cp /tmp/SecLists/Discovery/Web-Content/common.txt config/wordlists/paths-common.txt
cp /tmp/SecLists/Discovery/Web-Content/raft-large-directories.txt config/wordlists/paths-large.txt
cp /tmp/SecLists/Discovery/DNS/subdomains-top1million-5000.txt config/wordlists/subdomains-5000.txt

# Clean up
rm -rf /tmp/SecLists
```

### Option 2: Download individual files

```bash
curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
  -o config/wordlists/paths-common.txt

curl -sL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt \
  -o config/wordlists/subdomains-5000.txt
```

## Fallback Behavior

If these files are not present, the discovery modules fall back to their built-in
hardcoded wordlists (~250 paths, ~115 params, ~550 subdomains). The built-in lists
are curated for quality over quantity and work well for standard scans.

When files are present, they are **merged** with the hardcoded lists (hardcoded entries
first for priority, then file entries, deduplicated). This ensures the curated
high-value entries always appear at the top of the list.

## File Format

One entry per line. Lines starting with `#` are treated as comments and ignored.
Empty lines are ignored. Path entries without a leading `/` will have one prepended
automatically.
