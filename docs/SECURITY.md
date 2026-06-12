# Security Model & Threat Assessment

This document outlines the security boundaries, guarantees, and limitations of the OTP Encryption System.

## Threat Model

### Adversary Capabilities Assumed
- **Full Ciphertext Access**: The adversary possesses the complete `.enc` file.
- **Compute Power**: The adversary possesses nation-state-level compute, including theoretical scalable quantum computing (OTP is post-quantum secure).
- **Knowledge of Algorithm**: The adversary has the full source code of this tool.

### Adversary Capabilities Excluded
- **Host Compromise**: The system running the encryption/decryption is assumed to be free of malware, keyloggers, and hardware trojans.
- **Key Access**: The adversary does not possess the `.key` file.

## Cryptographic Guarantees

If the threat model holds, this system provides **Information-Theoretic Security (Perfect Secrecy)** for confidentiality.

Because the key is strictly equal to the length of the plaintext and is generated using a FIPS-compliant CSPRNG (`BCryptGenRandom` on Windows), an adversary with the ciphertext learns exactly *zero* bits about the plaintext. Every possible plaintext of length $N$ is equally likely.

### Integrity

Vanilla OTP provides **zero** integrity (it is highly malleable). An adversary flipping bit $i$ in the ciphertext will flip bit $i$ in the decrypted plaintext.

To mitigate this, this tool prepends a **SHA-256 digest** of the unencrypted plaintext to the ciphertext header.
*   **Guarantee**: Accidental corruption or intentional tampering will be detected upon decryption.
*   **Limitation**: This is not an HMAC. An adversary *could* theoretically construct a new plaintext, hash it, encrypt it with the key (if they had the key), and spoof the header. However, without the key, they cannot forge a valid ciphertext+hash combination that decrypts to a specific meaningful message.

## Key Management and Limitations

The entire security model collapses if key management fails.

1. **Key Reuse**: OTP is entirely broken if a key is reused. This tool attempts to prevent this locally by creating a `.lock` sidecar file immediately upon first use.
2. **Key Transmission**: The key must be transmitted out-of-band with absolute security. Communicating the key securely is as difficult as communicating the original plaintext securely.
3. **Hardware Storage (SSD Caveat)**: Using `--self-destruct-key` performs a 3-pass overwrite (`0x00`, `0xFF`, `0x00`) before file deletion. **However, on modern SSDs, wear-leveling firmware may redirect writes to new blocks, leaving the original key data intact on the flash medium.**
    *   *Mitigation*: For high-assurance environments, keys must reside on hardware tokens, RAM disks, or volumes protected by Full Disk Encryption (e.g., BitLocker) where the volume master key is destroyed.

## OTP vs AES-256-GCM

Why use this tool over AES-256-GCM (which is the industry standard)?

| Feature | OTP | AES-256-GCM |
| :--- | :--- | :--- |
| **Confidentiality** | Information-Theoretic (Perfect) | Computational (Strong) |
| **Post-Quantum** | Secure | Mostly Secure (Grover's bound to 128-bit) |
| **Key Size** | $O(N)$ (Must equal data size) | $O(1)$ (256 bits) |
| **Authentication** | Hash-based (detects tampering) | Built-in (AEAD) |
| **Practicality** | Very Low | Very High |

Use this OTP tool when you have an absolutely secure out-of-band channel for large keys (e.g., physical hard drive delivery) and require mathematical guarantees against future computational breakthroughs. For 99.9% of software engineering tasks, use AES-256-GCM.
