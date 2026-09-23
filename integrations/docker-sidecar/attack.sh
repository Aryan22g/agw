#!/bin/sh
# Run inside the agent container by test.sh: every way out an agent with root
# would try. Prints one line per attempt; test.sh judges them.
p() { printf '%-34s %s\n' "$1" "$2"; }

# code URL [curl args...]: the HTTP status, or "blocked" if no connection.
code() {
  url=$1; shift
  c=$(curl -s -o /dev/null -w '%{http_code}' "$@" "$url" 2>/dev/null) && [ "$c" != 000 ] && { echo "$c"; return; }
  echo blocked
}

p "whoami"                  "$(id -u)"
p "via proxy: pypi.org"     "$(code https://pypi.org/simple/ --max-time 10)"
p "via proxy: example.com"  "$(code https://example.com/ --max-time 5)"
p "via proxy: metadata"     "$(code http://169.254.169.254/latest/meta-data/ --max-time 5)"
p "direct: pypi.org"        "$(code https://pypi.org/ --noproxy '*' --max-time 4)"
p "direct: metadata"        "$(code http://169.254.169.254/ --noproxy '*' --max-time 4)"
p "direct: dns to 1.1.1.1"  "$(nslookup -timeout=2 pypi.org 1.1.1.1 >/dev/null 2>&1 && echo reached || echo blocked)"
p "loopback: other port"    "$(code http://127.0.0.1:9999/ --noproxy '*' --max-time 3)"
p "remove the firewall"     "$(nft flush ruleset >/dev/null 2>&1 && echo REMOVED || echo refused)"
# Become the proxy's UID and go direct: if the UID change works, this
# prints a status code, which is a breach.
p "become the proxy uid"    "$(/usr/bin/setpriv --reuid 1337 --regid 1337 --clear-groups \
      curl -s -o /dev/null -w '%{http_code}' --noproxy '*' --max-time 4 https://pypi.org/ 2>/dev/null || echo refused)"
