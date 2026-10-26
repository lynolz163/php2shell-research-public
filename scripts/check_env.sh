#!/usr/bin/env bash
# Record environment evidence: image digests, php version, SAPI, php.ini dump.
set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
ENVDIR="$ROOT/evidence/env"
mkdir -p "$ENVDIR"

for n in vuln-a fixed-a vuln-b fixed-b fpm-vuln fpm-fixed; do
    img=$(docker inspect --format '{{.Config.Image}}' "$n" 2>/dev/null) || continue
    did=$(docker inspect --format '{{.Image}}' "$n" 2>/dev/null)
    {
        echo "container: $n"
        echo "image: $img"
        echo "image_id: $did"
        docker image inspect "$img" --format 'repo_digest: {{index .RepoDigests 0}}' 2>/dev/null
    } > "$ENVDIR/$n.image.txt"
    if [[ "$n" == fpm-* ]]; then
        docker exec "$n" php -v   > "$ENVDIR/$n.php-v.txt" 2>&1
        docker exec "$n" php -i   > "$ENVDIR/$n.php-ini.txt" 2>&1
        docker exec "$n" php -m   > "$ENVDIR/$n.php-modules.txt" 2>&1
    else
        docker exec "$n" php -v   > "$ENVDIR/$n.php-v.txt" 2>&1
        docker exec "$n" php -i   > "$ENVDIR/$n.php-ini.txt" 2>&1
        docker exec "$n" php -m   > "$ENVDIR/$n.php-modules.txt" 2>&1
    fi
    echo "[+] evidence recorded for $n ($img)"
done

echo "[*] baseline HTTP checks:"
for p in 28081 28082 28083 28084 28085 28086; do
    echo "--- port $p ---" >> "$ENVDIR/baseline.txt"
    curl -s --max-time 5 "http://127.0.0.1:$p/index.php" >> "$ENVDIR/baseline.txt" 2>&1
    echo >> "$ENVDIR/baseline.txt"
done
cat "$ENVDIR/baseline.txt"
