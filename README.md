![Python](https://img.shields.io/badge/python-3670A0?style=for-the-badge&logo=python&logoColor=ffdd54)
![Flask](https://img.shields.io/badge/flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)
![License](https://img.shields.io/badge/License-Polyform_NC-red?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-MVP_Stable-green?style=for-the-badge)
![DRM](https://img.shields.io/badge/DRM-ClearKey_Orchestration-orange?style=for-the-badge)

# CoreStream

## Safeguarding Media Assets and Service Quality in Low-Trust Infrastructures

CoreStream is a lightweight orchestration framework designed to protect high-value content where standard DRM reach is limited. It provides a robust, end-to-end bridge between license delivery and secure playback, optimized for edge environments and private distribution networks.

---

## 🏛️ Architecture Overview

CoreStream implements a hybrid cryptographic model to ensure that content keys are never exposed in transit, even in compromised or low-trust networks.

- **Asymmetric Key Exchange**: Uses RSA-OAEP (SHA-256) for secure session key negotiation between the CDM and the Licensing Server.
- **Symmetric Content Delivery**: Employs AES-128-CBC with dynamic IV generation for high-performance payload encryption.
- **Encrypted Storage-at-Rest**: License data is persisted using a secondary AES-CTR master-key layer to prevent unauthorized local access.

---

## 🚀 Key Features

- 🛡️ **Adaptive Protection**: Dynamic license orchestration designed for semi-secure endpoints where Widevine L1 is unavailable.
- ⚡ **Edge-Optimized**: Minimal overhead Flask-based core, perfect for local servers in transport (Aviation/Bus) or offline environments.
- 🔑 **Secure Provisioning**: Built-in administrative dashboard for rapid content key ingestion and "Bunker" management.
- 🧩 **Standard Compliant**: Architecture follows CENC (Common Encryption) logic for seamless player integration.

---

## 🛠️ Quick Start

### 1. Environment Setup

Ensure you have your RSA keypair and master storage keys defined in your environment:

```bash
export MASTER_KEY_STORAGE="your_16_byte_key"
export ADMIN_PASSWORD="your_secure_password"
```

### 2. Launch the Ecosystem

1. **Start the Backend**: Run your `cdm_bridge.py` (it will handle the orchestration with the Bunker).
2. **Serve the Frontend**: Use a local server (like `python -m http.server 8000`) in the root directory.
3. **Access**: 
   - `http://localhost:8000/index.html` to browse content.
   - `http://localhost:8000/mvp360.html` for the VR experience.

---

## 📼 Content Preparation

CoreStream is content-agnostic and follows the **ISO/IEC 23001-7 (CENC)** standard. To prepare your assets for this framework:

1. **Transcode & Package**: Use tools like `FFmpeg` or `Shaka Packager`.
2. **Encryption**: Encrypt your DASH/HLS streams using **AES-128** (Common Encryption).
3. **Key Mapping**: Ensure the `KeyID` used during encryption is registered in the CoreStream Bunker via the Admin Panel.

> **Note**: For security and repository size constraints, encrypted media assets (`.mpd`, `.m3u8`) are not included. Users should point the players (`player.html` or `mvp360.html`) to their own secured DASH manifests.

## 🔐 Security Philosophy

CoreStream focuses on Transport-Layer Cryptography and License Orchestration.

While the final key handoff to the player (Shaka Player/MSE) follows a ClearKey-compliant flow, CoreStream ensures that the Acquisition Phase is fully hardened.

- **Hardened Acquisition**: Unlike standard ClearKey implementations where the key is often fetched in plain JSON, CoreStream wraps the entire request/response in a signed RSA-OAEP and AES-CBC envelope.

- **MITM Mitigation**: By using a private exchange, we prevent Man-in-the-Middle (MITM) attacks and unauthorized license harvesting during the transit over the "Last Mile" of the network.

- **Operational Obfuscation**: The architecture is designed to add a layer of robust security to environments where a hardware-backed TEE (Trusted Execution Environment) is not available or commercially viable.

## 🌐 Frontend Ecosystem

CoreStream is not just a backend; it includes a complete suite of client-side implementations:

* **`index.html`**: A modern landing page and content gallery to showcase your media library.
* **`player.html`**: A standard high-performance web player powered by Shaka Player, featuring dynamic license fetching from the `cdm_bridge`.
* **`mvp360.html`**: An immersive VR experience using **A-Frame**. This module demonstrates 360° video playback with real-time DRM decryption, ideal for advanced streaming use cases.



---

## 🧩 Third-Party Components
This project uses **Shaka Player** (Apache 2.0) for media playback. 
Special thanks to the Google Shaka Player team for their open-source contribution.

## ⚖️ License & Commercial Use

This project is licensed under the Polyform Noncommercial License 1.0.0.

✅ **Permitted**: Personal study, research, academic projects, and non-commercial testing.

❌ **Prohibited**: Any commercial application, including use in private companies, paid services, or commercial transport entertainment systems.

**Note for Enterprises**: If you are interested in a commercial license, private deployment, or technical consultancy regarding this architecture, please contact the author via [LinkedIn](https://www.linkedin.com/in/arnauquest).
