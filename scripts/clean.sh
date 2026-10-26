#!/usr/bin/env bash
# Remove php2shell-research containers and its dedicated network ONLY.
# Never touches any other Docker resource (no system prune, no volume wipe).
set -u
for n in vuln-a fixed-a vuln-b fixed-b fpm-vuln fpm-fixed \
         fpm-vuln-nginx fpm-fixed-nginx; do
    docker rm -f "$n" >/dev/null 2>&1 || true
done
docker network rm php2shell-net >/dev/null 2>&1 && echo "[-] network removed" || true
echo "[*] php2shell-research resources cleaned"
