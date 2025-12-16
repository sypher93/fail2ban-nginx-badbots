# Fail2ban Nginx BadBots Filter

## Description
Advanced fail2ban filter for Nginx that protects against common web attacks including OWASP Top 10 vulnerabilities, path traversal, code injection, SQL injection, XSS, malicious bots, and Django-specific exploits.
This filter is the one I use for deploying my Django applications on the internet, so it has been battle-tested and works quite well, which is why I'm sharing it.

## Features
- **OWASP Top 10 Protection**: SQL injection, XSS, path traversal, RCE
- **Common CMS/Admin Exploits**: WordPress, phpMyAdmin, admin panels
- **Django Framework Security**: Settings, migrations, debug endpoints
- **Sensitive File Detection**: Backups, configs, keys, databases
- **Malicious Bot Prevention**: Scanners, null requests, hex payloads
- **API & Development Tools**: Swagger, GraphQL, package managers

## Installation

### 1. Create the filter
```bash
sudo nano /etc/fail2ban/filter.d/nginx-badbots-filter.conf
```

Paste the filter configuration (see below).

### 2. Configure the jail
```bash
sudo nano /etc/fail2ban/jail.local
```

Add the jail configuration (see below).

### 3. Restart fail2ban
```bash
sudo systemctl restart fail2ban
sudo fail2ban-client status nginx-badbots
```

## Filter Configuration

**File**: `/etc/fail2ban/filter.d/nginx-badbots-filer.conf`

```ini
[Definition]

# Line 1-2: WordPress, phpMyAdmin, .env files, admin panels, Django settings
failregex = ^<HOST> -.*"(GET|POST|HEAD).*(wp-|phpmyadmin|\.env|\.git|admin|settings\.py|\.php).*"

# Line 3: Path traversal attacks (../, /etc/, /proc/, /sys/)
            ^<HOST> -.*"(GET|POST|HEAD).*(\.\.\/|\.\.\\|\/etc\/|\/proc\/|\/var\/|\/sys\/|\/dev\/).*"

# Line 4: Remote code execution (eval, exec, system, shell_exec)
            ^<HOST> -.*"(GET|POST|HEAD).*(base64_|eval\(|system\(|exec\(|shell_exec|passthru|cmd=|command=).*"

# Line 5: SQL injection patterns (UNION SELECT, hex encoding, time-based)
            ^<HOST> -.*"(GET|POST|HEAD).*(union.*select|concat\(|substring\(|0x[0-9a-f]+|sleep\(|benchmark\().*" [NC]

# Line 6: XSS attacks (script tags, iframe, javascript:, event handlers)
            ^<HOST> -.*"(GET|POST|HEAD).*(script>|<iframe|<object|javascript:|onerror=|onload=).*" [NC]

# Line 7: Backup and sensitive file access (.bak, .sql, .zip, dump)
            ^<HOST> -.*"(GET|POST|HEAD).*(\.bak|\.old|\.log|\.sql|\.tar|\.zip|\.rar|backup|dump).*"

# Line 8: CGI and script execution attempts
            ^<HOST> -.*"(GET|POST|HEAD).*(xmlrpc|cgi-bin|\.cgi|\.pl|\.sh|\.py|\.rb).*"

# Line 9: Java/Tomcat management interfaces
            ^<HOST> -.*"(GET|POST|HEAD).*(actuator|jolokia|jmx-console|manager/html|tomcat).*"

# Line 10: Cloud credentials and SSH keys
            ^<HOST> -.*"(GET|POST|HEAD).*(aws|s3|\.pem|\.key|id_rsa|authorized_keys).*"

# Line 11: CI/CD and version control files
            ^<HOST> -.*"(GET|POST|HEAD).*(hudson|jenkins|\.svn|\.hg|\.DS_Store).*"

# Line 12: Package manager files
            ^<HOST> -.*"(GET|POST|HEAD).*(composer\.json|package\.json|yarn\.lock|Gemfile).*"

# Line 13: API documentation endpoints
            ^<HOST> -.*"(GET|POST|HEAD).*(swagger|api-docs|graphql|\.json\?|\.xml\?).*"

# Line 14: Null byte and encoding attacks
            ^<HOST> -.*"(GET|POST|HEAD).*(%%00|%%0d|%%0a|%%09|\\x00|\\r\\n).*"

# Line 15-16: Django core files and settings
            ^<HOST> -.*"(GET|POST|HEAD).*(settings\.py|urls\.py|wsgi\.py|asgi\.py|manage\.py).*"
            ^<HOST> -.*"(GET|POST|HEAD).*(django\.settings|DJANGO_SETTINGS_MODULE).*"

# Line 17: Django migrations and compiled Python
            ^<HOST> -.*"(GET|POST|HEAD).*(\/migrations\/|__pycache__|\.pyc|\.pyo).*"

# Line 18: Django/SQLite database files
            ^<HOST> -.*"(GET|POST|HEAD).*(db\.sqlite3|\.db|database\.sqlite).*"

# Line 19: Python dependency files
            ^<HOST> -.*"(GET|POST|HEAD).*(requirements\.txt|Pipfile|poetry\.lock|setup\.py).*"

# Line 20: Django static/media directories
            ^<HOST> -.*"(GET|POST|HEAD).*(\/static\/admin|\/media\/|STATIC_ROOT|MEDIA_ROOT).*"

# Line 21: Django admin actions
            ^<HOST> -.*"(GET|POST|HEAD).*(\/admin\/.*\/add|\/admin\/.*\/delete|\/admin\/auth).*"

# Line 22: Django configuration secrets
            ^<HOST> -.*"(GET|POST|HEAD).*(SECRET_KEY|DEBUG.*True|ALLOWED_HOSTS).*"

# Line 23: Python virtual environments
            ^<HOST> -.*"(GET|POST|HEAD).*(\/\.venv\/|\/venv\/|\/env\/|site-packages).*"

# Line 24: Task queue and caching services
            ^<HOST> -.*"(GET|POST|HEAD).*(celery|redis|rabbitmq|flower).*"

# Line 25: Django REST framework documentation
            ^<HOST> -.*"(GET|POST|HEAD).*(\/api\/schema|\/api\/docs|drf-spectacular).*"

# Line 26: Django debug tools
            ^<HOST> -.*"(GET|POST|HEAD).*(__debug__|debug_toolbar|silk\/requests).*"

# Line 27-29: Empty requests, hex payloads, SSH probes
            ^<HOST> -.*"" 400 0 "-" "-"
            ^<HOST> -.*"\\x[0-9A-Fa-f]{2}.*" 400
            ^<HOST> -.*"SSH-.*" 400

# Line 30: WordPress XML-RPC attacks
            ^<HOST> -.*"(GET|POST|HEAD).*(wlwmanifest\.xml|xmlrpc\.php\?rsd).*"

ignoreregex =
```

## Jail Configuration

**File**: `/etc/fail2ban/jail.local`

```ini
[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots-filter
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 86400
action = iptables-multiport[name=BadBots, port="http,https", protocol=tcp]
ignoreip = 127.0.0.1/8 ::1 YOUR_IP_HERE
```

## Configuration Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| `maxretry` | 2 | Ban after 2 malicious attempts |
| `findtime` | 600 | Time window: 10 minutes |
| `bantime` | 86400 | Ban duration: 24 hours |
| `logpath` | `/var/log/nginx/access.log` | Adjust to your Nginx log path |

## Testing

```bash
# Test the filter against your logs
sudo fail2ban-regex /var/log/nginx/access.log /etc/fail2ban/filter.d/nginx-badbots-filter.conf

# Check banned IPs
sudo fail2ban-client status nginx-badbots

# Unban an IP manually
sudo fail2ban-client set nginx-badbots unbanip IP_ADDRESS
```

## Recommendations

1. **Adjust `logpath`**: Match your actual Nginx access log location
2. **Whitelist your IP**: Add your IP to `ignoreip` to avoid self-banning
3. **Monitor initially**: Set `bantime = 3600` (1 hour) during testing
4. **Review logs**: Check `/var/log/fail2ban.log` for false positives
5. **Combine filters**: Use alongside `nginx-noscript`, `nginx-noproxy`

## License
GNU v3

## Contributing
Issues and pull requests welcome!

## Disclaimer

This filter provides strong protection but should be part of a layered security approach including:

- Regular software updates
- Strong authentication
- HTTPS/TLS encryption
- Web Application Firewall (WAF)
- Rate limiting
- Security headers

## Resources

- [Fail2ban Documentation](https://fail2ban.readthedocs.io/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Nginx Security](https://nginx.org/en/docs/http/ngx_http_core_module.html#satisfy)

## Support

- **Issues**: Open an issue on GitHub
- **Questions**: Check existing issues or start a discussion

---

**⭐ If this filter helps secure your server, please star the repository!**

