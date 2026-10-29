#!/bin/sh
# Actualizare MANUALĂ a serverului NVR proxy din GitHub (rulată de utilizator, nu automat).
# Descarcă server.js, îl verifică, îl instalează și revine la versiunea anterioară dacă nu pornește.
REF="${REF:-main}"   # se poate fixa un commit: REF=<sha> (ocolește cache-ul GitHub)
URL="https://raw.githubusercontent.com/Yoskoyos/Yoskoyos.github.io/$REF/server/server.js"
DIR=/opt/nvr-proxy
cd "$DIR" || { echo "Nu găsesc $DIR"; exit 1; }
echo "Descarc versiunea nouă..."
curl -fsSL --max-time 30 "$URL?t=$(date +%s)" -o server.new.js || { echo "EROARE: descărcarea a eșuat"; exit 1; }
if ! node --check server.new.js 2>/dev/null; then echo "EROARE: fișier invalid, nu instalez nimic"; rm -f server.new.js; exit 1; fi
if cmp -s server.new.js server.js; then rm -f server.new.js; echo "Serverul are deja ultima versiune."; curl -s http://localhost:3000/health; echo; exit 0; fi
if ! command -v ffmpeg >/dev/null 2>&1; then
  echo "Instalez ffmpeg (pentru imaginile din stream RTSP)..."
  (apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ffmpeg) >/dev/null 2>&1 || echo "ATENȚIE: ffmpeg nu s-a instalat — restul merge normal"
fi
# contracte PDF: nginx acceptă implicit doar 1 MB → ridicăm limita la 25 MB (o singură dată)
NG=$(grep -ls "server_name proxy.supraveghere24h.ro" /etc/nginx/sites-enabled/* /etc/nginx/conf.d/*.conf 2>/dev/null | head -1)
if [ -n "$NG" ]; then
  NG=$(readlink -f "$NG")
  if ! grep -q client_max_body_size "$NG"; then
    cp "$NG" /root/nginx-nvr-proxy.conf.bak
    sed -i '0,/server_name proxy.supraveghere24h.ro;/s//&\n    client_max_body_size 25m;/' "$NG"
    if nginx -t >/dev/null 2>&1; then systemctl reload nginx; echo "nginx: limită upload 25 MB"; else cp /root/nginx-nvr-proxy.conf.bak "$NG"; echo "ATENȚIE: nu am putut modifica nginx (restaurat)"; fi
  fi
fi
[ -d node_modules/nodemailer ] || npm install --silent nodemailer@6 >/dev/null 2>&1 || true
cp server.js server.js.prev
mv server.new.js server.js
systemctl restart nvr-proxy
sleep 4
if curl -fs --max-time 5 http://localhost:3000/health >/dev/null; then
  echo "GATA — server actualizat:"
  curl -s http://localhost:3000/health; echo
else
  echo "Serverul nou nu răspunde — revin la versiunea anterioară."
  cp server.js.prev server.js
  systemctl restart nvr-proxy
fi
