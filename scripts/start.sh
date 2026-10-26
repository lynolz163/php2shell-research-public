#!/usr/bin/env bash
# php2shell-research lab launcher (plain Docker CLI; no compose plugin needed).
# Binds every service to 127.0.0.1 only. Applies per-container resource limits.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
NET="php2shell-net"

docker network create "$NET" 2>/dev/null || true

LOGROOT="$ROOT/evidence/logs"
for n in vuln-a fixed-a vuln-b fixed-b fpm-vuln fpm-fixed; do
    mkdir -p "$LOGROOT/$n/apache" "$LOGROOT/$n/php"
done

mk_nginx_conf() { # $1 = fpm container name, $2 = output file
    sed "s/{{FPM_HOST}}/$1/" "$ROOT/config/nginx-fpm.conf.template" > "$2"
}

run_modphp() { # name image port
    local name="$1" image="$2" port="$3"
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" --hostname "$name" --network "$NET" \
        -p "127.0.0.1:${port}:80" \
        -m 512m --cpus=1 --pids-limit=128 \
        -v "$ROOT/webroot":/var/www/html:ro \
        -v "$ROOT/config/php-lab.ini":/usr/local/etc/php/conf.d/zz-lab.ini:ro \
        -v "$ROOT/config/apache-vhost.conf":/etc/apache2/sites-enabled/000-default.conf:ro \
        -v "$LOGROOT/$name/apache":/var/log/apache2 \
        "$image" >/dev/null
    echo "[+] $name  ($image)  http://127.0.0.1:$port/index.php"
}

run_fpm() { # name image port (php-fpm) + nginx sidecar
    local name="$1" image="$2" port="$3"
    local proxy="$name-nginx"
    docker rm -f "$name" "$proxy" >/dev/null 2>&1 || true
    mk_nginx_conf "$name" "$ROOT/config/nginx-$name.conf"
    # also publish FPM 9000 for direct FastCGI experiments:
    # fpm-vuln(28085) -> 29000, fpm-fixed(28086) -> 29001
    docker run -d --name "$name" --hostname "$name" --network "$NET" \
        -p "127.0.0.1:$((port + 915)):9000" \
        -m 512m --cpus=1 --pids-limit=128 \
        -v "$ROOT/webroot":/var/www/html:ro \
        -v "$ROOT/config/php-lab.ini":/usr/local/etc/php/conf.d/zz-lab.ini:ro \
        -v "$LOGROOT/$name/php":/var/log/php \
        "$image" >/dev/null
    docker run -d --name "$proxy" --hostname "$proxy" --network "$NET" \
        -p "127.0.0.1:${port}:80" \
        -m 128m --cpus=0.5 --pids-limit=64 \
        -v "$ROOT/webroot":/var/www/html:ro \
        -v "$ROOT/config/nginx-$name.conf":/etc/nginx/conf.d/default.conf:ro \
        nginx:alpine >/dev/null
    echo "[+] $name  ($image + nginx)  http://127.0.0.1:$port/index.php"
}

run_modphp vuln-a   php:8.4.26-apache 28081
run_modphp fixed-a  php:8.4.27-apache 28082
run_modphp vuln-b   php:8.3.35-apache 28083
run_modphp fixed-b  php:8.3.36-apache 28084
run_fpm    fpm-vuln  php:8.4.26-fpm   28085
run_fpm    fpm-fixed php:8.4.27-fpm   28086

echo "[*] waiting for services..."
ok=0
for i in $(seq 1 30); do
    ok=1
    for p in 28081 28082 28083 28084 28085 28086; do
        curl -s -o /dev/null --max-time 2 "http://127.0.0.1:$p/index.php" || ok=0
    done
    [ "$ok" = 1 ] && break
    sleep 1
done
if [ "$ok" = 1 ]; then
    echo "[+] all 6 endpoints up"
else
    echo "[!] some endpoints not responding yet - check docker logs"
fi
