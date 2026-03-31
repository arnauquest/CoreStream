# -----------------------------------------------------------------------------
# Project: CoreStream - Multimedia Asset Safeguarding Framework
# File: cdm_bridge.py
# Author: Arnau Taberner García
# Based on a colective work of Security and Rights Manegement with Paula Gacía Martínez, Arnau Taberner García, and others.
# Copyright (c) 2025-2026 Arnau Taberner García. All rights reserved.
#
# License: PolyForm Noncommercial License 1.0.0
# This software is licensed for non-commercial, educational, and 
# research purposes only. Commercial use is strictly prohibited without 
# a separate commercial license from the author.
#
# Documentation & Legal: https://github.com/arnauquest/CoreStream
# -----------------------------------------------------------------------------

import base64
import json
import requests
import os
from flask import Flask, request, jsonify
from flask_cors import CORS
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

app = Flask(__name__)
CORS(app)

VPS_LICENSE_URL     = "127.0.0.1:5000/get-license" # Cambia esto por la URL real de tu Servidor de Licencias
PUBLIC_KEY_VPS_PATH = "public_key_vps.pem" # Ruta al certificado público del servidor para cifrar el payload

def pad(data):
    remainder = len(data) % 16
    if remainder == 0:
        return data + (b" " * 16)
    return data + (b" " * (16 - remainder))

def extract_kid_from_challenge(challenge_str):
    """
    El challenge de ClearKey/Widevine es un JSON en base64:
      {"kids": ["MDAxAAAAAAAAAAAAAAAAAAA"], "type": "temporary"}
    Devuelve el primer KID tal como viene (base64url), que es lo que
    el servidor tiene registrado.
    """
    try:
        # Añadir padding base64 si falta
        padded = challenge_str + "==" 
        decoded = json.loads(base64.urlsafe_b64decode(padded).decode('utf-8'))
        kid = decoded['kids'][0]
        print(f"  KID extraido del challenge: '{kid}'")
        return kid
    except Exception as e:
        print(f"  No se pudo parsear el challenge como ClearKey JSON: {e}")
        return None

@app.route('/license', methods=['POST'])
def cdm_proxy():
    data      = request.json
    user      = data.get('user', '')
    challenge = data.get('challenge', '')

    print(f"\n--- Nueva peticion de licencia ---")
    print(f"  usuario  : {user}")

    # Intentar extraer el KID real del challenge
    kid = extract_kid_from_challenge(challenge)
    if not kid:
        # Fallback al KID manual si el challenge no es parseable
        kid = data.get('kid', '001')
        print(f"  KID fallback: '{kid}'")

    print(f"  KID final: '{kid}' (len={len(kid)})")

    try:
        session_key = os.urandom(16)
        iv_request  = os.urandom(16)

        with open(PUBLIC_KEY_VPS_PATH, "rb") as f:
            public_key_vps = serialization.load_pem_public_key(f.read())

        encrypted_aes_key = public_key_vps.encrypt(
            session_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        payload_str  = f"{len(kid):02d}{kid}{challenge}"
        payload_data = pad(payload_str.encode('utf-8'))
        print(f"  payload enviado: {payload_str[:60]}{'...' if len(payload_str)>60 else ''!r}")

        enc = Cipher(algorithms.AES(session_key), modes.CBC(iv_request)).encryptor()
        encrypted_payload = enc.update(payload_data) + enc.finalize()

        print("  Enviando al VPS...")
        vps_response = requests.post(VPS_LICENSE_URL, json={
            "encrypted_key": base64.b64encode(encrypted_aes_key).decode(),
            "iv":            base64.b64encode(iv_request).decode(),
            "payload":       base64.b64encode(encrypted_payload).decode()
        }, timeout=10)

        print(f"  VPS HTTP status: {vps_response.status_code}")

        if vps_response.status_code != 200:
            return jsonify({"error": "Error HTTP en el Bunker", "details": vps_response.text}), 500

        resp_data    = vps_response.json()
        iv_resp      = base64.b64decode(resp_data['iv'])
        payload_resp = base64.b64decode(resp_data['payload'])

        dec = Cipher(algorithms.AES(session_key), modes.CBC(iv_resp)).decryptor()
        decrypted_raw = dec.update(payload_resp) + dec.finalize()
        res_text = decrypted_raw.decode('utf-8', errors='replace').strip()
        print(f"  Respuesta del bunker: {res_text!r}")

        if "200 FOUND:" in res_text:
            content_key = res_text.split(":", 1)[1]
            print(f"  content_key: '{content_key}' (len={len(content_key)})")

            # Devolver al player el KID y KEY tal como los necesita ClearKey
            return jsonify({
                "kids": [kid],
                "keys": [{
                    "kid": kid,
                    "key": base64.urlsafe_b64encode(content_key.encode('utf-8')).decode().rstrip('=')
                }]
            })

        print(f"  BUNKER ERROR: {res_text}")
        return jsonify({"error": res_text}), 404

    except Exception as e:
        import traceback
        print(f"EXCEPCION: {e}")
        traceback.print_exc()
        return jsonify({"error": str(e)}), 500


@app.route('/ping-bunker', methods=['GET'])
def ping_bunker():
    """Test: GET /ping-bunker?kid=MDAxAAAAAAAAAAAAAAAAAAA"""
    kid_test = request.args.get('kid', '001')
    with app.test_client() as c:
        # Simular un challenge ClearKey real con ese KID
        fake_challenge = base64.urlsafe_b64encode(
            json.dumps({"kids": [kid_test], "type": "temporary"}).encode()
        ).decode().rstrip('=')
        r = c.post('/license',
                   json={'challenge': fake_challenge, 'user': 'debug'},
                   content_type='application/json')
        return r.data, r.status_code, {'Content-Type': 'application/json'}


if __name__ == '__main__':
    print("--- CDM ACTIVO ---")
    app.run(host='0.0.0.0', port=5001, debug=True) # Cambia el puerto si es necesario y desactiva debug en producción