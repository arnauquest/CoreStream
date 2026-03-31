# -----------------------------------------------------------------------------
# Project: CoreStream - Multimedia Asset Safeguarding Framework
# File: license_server.py
# Author: Arnau Taberner García
# Copyright (c) 2025-2026 Arnau Taberner García. All rights reserved.
#
# License: PolyForm Noncommercial License 1.0.0
# This software is licensed for non-commercial, educational, and 
# research purposes only. Commercial use is strictly prohibited without 
# a separate commercial license from the author.
#
# Documentation & Legal: https://github.com/arnauquest/CoreStream
# -----------------------------------------------------------------------------

from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import hashlib
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)
CORS(app) 

# --- CONFIGURACIÓN ---
MASTER_KEY_STORAGE = os.getenv("MASTER_KEY_STORAGE").encode()  # Clave maestra para cifrar el archivo de licencias (16 bytes)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")

# --- FUNCIONES DE AYUDA PARA BLOQUES DE 16 BYTES ---
def pad(data):
    """Rellena con espacios hasta que sea múltiplo de 16 para AES-CBC."""
    return data + (b" " * (16 - len(data) % 16))

def unpad(data):
    """Limpia los espacios del relleno."""
    return data.strip()

# --- PANEL DE ADMINISTRACIÓN ---
@app.route('/admin', methods=['GET'])
def admin_panel():
    return '''
    <!DOCTYPE html>
    <html>
    <head><title>Ioryxtech Admin</title><style>
        body { font-family: sans-serif; background: #1a1a1a; color: white; display: flex; justify-content: center; padding-top: 50px; }
        .box { background: #2a2a2a; padding: 20px; border-radius: 8px; box-shadow: 0 4px 15px rgba(0,0,0,0.5); }
        input { display: block; width: 100%; margin: 10px 0; padding: 8px; border-radius: 4px; border: none; }
        button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; border-radius: 4px; cursor: pointer; }
    </style></head>
    <body>
        <div class="box">
            <h2>🔑 Registro de Licencias</h2>
            <input type="password" id="pass" placeholder="Password Admin">
            <hr>
            <input type="text" id="kid" placeholder="Key ID (ej: 001)">
            <input type="text" id="key" placeholder="Content Key (16 chars)">
            <button onclick="enviar()">Registrar en Búnker</button>
            <p id="msg"></p>
        </div>
        <script>
            async function enviar() {
                const res = await fetch('/admin/add-key', {
                    method: 'POST',
                    headers: {'Content-Type': 'application/json'},
                    body: JSON.stringify({
                        password: document.getElementById('pass').value,
                        kid: document.getElementById('kid').value,
                        key: document.getElementById('key').value
                    })
                });
                const data = await res.json();
                document.getElementById('msg').innerText = data.status || data.error;
            }
        </script>
    </body></html>
    '''

@app.route('/admin/add-key', methods=['POST'])
def add_key_web():
    data = request.json
    if data.get('password') != ADMIN_PASSWORD:
        return jsonify({"error": "Acceso denegado"}), 403
    
    kid = data.get('kid')
    key = data.get('key')
    
    if len(key) != 16:
        return jsonify({"error": "La llave debe tener 16 bytes"}), 400

    try:
        bunker.license_data[kid] = key
        lineas = "\n".join([f"{k}:{v}" for k, v in bunker.license_data.items()])
        
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(MASTER_KEY_STORAGE), modes.CTR(iv))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(lineas.encode()) + encryptor.finalize()
        
        with open("licenses.enc", "wb") as f:
            f.write(iv + ciphertext)
            
        return jsonify({"status": f"Llave {kid} registrada con éxito"})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# --- LÓGICA DEL SERVIDOR DE LICENCIAS ---
class LicensingServer:
    def __init__(self):
        # Asegúrate de que estas carpetas existan y contengan las claves correctas
        with open("./myCerts/public_key.pem", "rb") as f:
            self.public_key = serialization.load_pem_public_key(f.read())
        with open("./myCerts/private.pem", "rb") as f:
            self.private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("./Client_certs/public_key_atabgar.pem", "rb") as f:
            self.client_public_key = serialization.load_pem_public_key(f.read())

        self.license_data = {}
        if os.path.exists("licenses.enc"):
            with open("licenses.enc", "rb") as f:
                contenido = f.read()
            iv = contenido[:16]
            ciphertext = contenido[16:]
            cipher = Cipher(algorithms.AES(MASTER_KEY_STORAGE), modes.CTR(iv))
            plaintext = cipher.decryptor().update(ciphertext) + cipher.decryptor().finalize()
            for line in plaintext.decode('utf-8').splitlines():
                if ":" in line:
                    k, v = line.strip().split(":")
                    self.license_data[k] = v

    def aes_crypt(self, data, key, iv, encrypt=True):
        # CAMBIO A CBC: Es vital para que coincida con el CDM y el Padding
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        op = cipher.encryptor() if encrypt else cipher.decryptor()
        return op.update(data) + op.finalize()

bunker = LicensingServer()

@app.route('/get-license', methods=['POST'])
def handle_license():
    try:
        data = request.json
        encrypted_aes_key = base64.b64decode(data['encrypted_key'])
        iv_request = base64.b64decode(data['iv'])
        encrypted_payload = base64.b64decode(data['payload'])

        # 1. Descifrar clave de sesión RSA usando OAEP (estándar que usa el CDM)
        session_key = bunker.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        session_key = session_key[-16:] # Nos aseguramos de que sean 16 bytes

        # 2. Descifrar el paquete (AES-CBC + Unpad)
        decrypted_packet_raw = bunker.aes_crypt(encrypted_payload, session_key, iv_request, encrypt=False)
        decrypted_packet = unpad(decrypted_packet_raw)
        
        # 3. Extraer KeyID (Formato: "02001...")
        # Los primeros 2 caracteres indican la longitud del KID
        len_kid = int(decrypted_packet[:2].decode())
        key_id_str = decrypted_packet[2:2+len_kid].decode().strip()
        
        print(f"Búnker: Petición para KID '{key_id_str}'")

        # 4. Buscar Licencia
        if key_id_str in bunker.license_data:
            content_key = bunker.license_data[key_id_str]
            respuesta = f"200 FOUND:{content_key}"
        else:
            respuesta = "404 ERROR:KeyID not found"

        # 5. Cifrar respuesta con PADDING (Evita el error de block length)
        iv_resp = os.urandom(16)
        # Aplicamos pad() antes de cifrar para que sea múltiplo de 16
        datos_cifrar = pad(respuesta.encode())
        resp_cipher = bunker.aes_crypt(datos_cifrar, session_key, iv_resp, encrypt=True)

        return jsonify({
            "iv": base64.b64encode(iv_resp).decode(),
            "payload": base64.b64encode(resp_cipher).decode()
        })

    except Exception as e:
        print(f"Error interno: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # Nota: Para producción, es recomendable usar un servidor WSGI como Gunicorn y configurar HTTPS con Nginx o similar.
    app.run(host='0.0.0.0', port=80) # Cambia a 443 si usas HTTPS y asegúrate de configurar el certificado SSL en Flask o usar un proxy inverso como Nginx para manejar TLS.