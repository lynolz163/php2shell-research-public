#!/usr/bin/env bash
# Stop all php2shell-research lab containers (project-scoped only).
set -u
for n in vuln-a fixed-a vuln-b fixed-b fpm-vuln fpm-fixed \
         fpm-vuln-nginx fpm-fixed-nginx; do
    docker rm -f "$n" >/dev/null 2>&1 && echo "[-] stopped $n" || true
done
echo "[*] done (network php2shell-net left in place; use clean.sh to remove)"
