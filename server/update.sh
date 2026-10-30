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
# imaginile din e-mailul cu oferta (servite de server la /email-img/)
mkdir -p "$DIR/email-img"
for f in hero.jpg i-img.png i-lock.png i-phone.png i-rec.png i-shield.png i-wrench.png p-bullet.png p-cab.png p-hdd.png p-nvr.png p-sw.png p-tech.png p-turret.png s-badge.png s-cam.png s-check.png s-gear.png s-key.png s-note.png s-shield.png s-shield2.png s-tool.png; do curl -fsSL --max-time 20 "https://raw.githubusercontent.com/Yoskoyos/Yoskoyos.github.io/$REF/server/email-img/$f" -o "$DIR/email-img/$f.tmp" && mv "$DIR/email-img/$f.tmp" "$DIR/email-img/$f"; done
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
# oferte: serverul are nevoie de IP-ul real al vizitatorului (limitare cereri) → X-Forwarded-For (o singură dată)
if [ -n "$NG" ] && ! grep -q "X-Forwarded-For" "$NG"; then
  cp "$NG" /root/nginx-nvr-proxy.conf.bak2
  sed -i '0,/proxy_set_header Host \$host;/s//&\n        proxy_set_header X-Forwarded-For $remote_addr;/' "$NG"
  if nginx -t >/dev/null 2>&1; then systemctl reload nginx; echo "nginx: IP real vizitatori"; else cp /root/nginx-nvr-proxy.conf.bak2 "$NG"; echo "ATENȚIE: nu am putut adăuga X-Forwarded-For (restaurat)"; fi
fi
[ -d node_modules/nodemailer ] || npm install --silent nodemailer@latest >/dev/null 2>&1 || true
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
