# Yeznsap v4.5 Threat Model

## Assets

- Recovery phrase (16 words).
- Client RSA-OAEP private identity key and ECDSA P-256 signing private key.
- Per-chat AES-256 keys.
- Message plaintext on the endpoints only.
- Server account/session metadata.
- Encrypted server store.

## Server compromise

For v4.5 accounts the server does not receive the recovery phrase. It stores a scrypt-protected derived authentication secret and an encrypted private-key backup. New message bodies are stored as AES-GCM ciphertext.

A server compromise can still expose metadata, public keys, wrapped chat keys, ciphertext, session state, and encrypted private-key bundles. Chat-key establishment is signed with the creator's ECDSA identity key, which detects silent replacement of an already established chat key. A malicious server can still attempt **first-contact identity substitution** before a fingerprint has been independently verified. Users should compare fingerprints out of band for high-value conversations.

## Database/file theft

`data/store.enc` is AES-256-GCM encrypted. Theft of the file alone should not reveal contents without the server data key. If the attacker gets the store key too, E2EE message bodies remain ciphertext, but account metadata and wrapped E2EE keys become visible. The attacker still needs an endpoint private key or recovery phrase to unwrap chat keys.

## Browser/device compromise

E2EE does not protect against malware, hostile browser extensions with sufficient privilege, OS compromise, or malicious code executing in Yeznsap's origin. Plaintext necessarily exists at the endpoints during display/composition.

## MITM

Production requires HTTPS. E2EE adds another layer for message content, but public-key authenticity at first contact is protected by user-verifiable fingerprints rather than a centralized transparency log in this version.

## Cryptographic limitations

The direct-message scheme is not Signal Protocol and has no Double Ratchet/PFS. It uses RSA identity encryption keys to unwrap a long-lived random AES chat key and ECDSA identity keys to authenticate the chat-key agreement. This is materially stronger than server-side-only encryption and resists silent server-side chat-key replacement after establishment, but it is not equivalent to Signal's forward secrecy/post-compromise properties.
