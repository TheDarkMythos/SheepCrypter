# SheepCrypter - Ghostly Hollowing Crypter
Advanced in-memory process injection using transient SEC_IMAGE sections, custom crypter, and ADS payload delivery no disk traces, maximum stealth.

This project demonstrates a stealthy process injection method combining process hollowing, transient SEC_IMAGE sections, and in-memory payload decryption using a custom crypter. The payload is stored in an Alternate Data Stream (ADS), decrypted at runtime, and mapped into a suspended target process without ever touching disk in plaintext form. No PE dumping, no persistent artifacts, and minimal forensic footprint.

Built for educational purposes, red team simulations, and research on modern malware evasion.

### Features:

    + Payload encryption with custom AES crypter

    + Storage in Alternate Data Stream (ADS)

    + In-memory decryption only (no disk I/O)

    + Section-based injection using NtCreateSection + NtMapViewOfSection

    + Ghostly hollowing via transient file-backed SEC_IMAGE sections

    + Cleanup of all traces (file handles, decryption key, etc.)

    + Compatible with modern Windows x64 (NT-based systems)

Disclaimer: This tool is provided for educational and ethical security research purposes only. Use it only in controlled environments with explicit authorization.
