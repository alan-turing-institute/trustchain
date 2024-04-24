---
hide:
  - footer
---
# Trustchain

Welcome to the Trustchain Docs website.

Trustchain is a decentralised approach to public key infrastructure, which builds on the W3C standards for [Decentralised Identifiers (DID)](https://www.w3.org/TR/did-core/) and [Verifiable Credentials (VC)](https://www.w3.org/TR/vc-data-model-2.0/).

These two standards are closely linked: verifying a credential involves resolving the issuer's DID document and performing a verification procedure using material contained in that document. Typically the verification material is a cryptographic [public key](https://en.wikipedia.org/wiki/Public-key_cryptography), in which case the procedure is to use the key to verify the issuer's digital signature on the credential.

Trustchain enables the creation of DIDs which are themselves verifiable. Via this mechanism, chains of trustworthy DIDs can be constructed in which **downstream DIDs** (dDIDs) contain an attestation from an entity represented by an **upstream DID** (uDID). It also enables a **root DID** to be securely established, so that downstream DIDs can be verified by tracing their chain of attestions back to the recognised root.

Trustchain is free and open source software. The setup and operational costs of the system are low, without compromising on security or resilience, because it is built upon existing, robust peer-to-peer networks. It is globally accessible and can operate at any social scale, making it freely available for any user community to adopt.

# Trustchain Mobile

Trustchain Mobile is a mobile app built to demonstrate the Trustchain user experience, from the perspective of a holder and/or verifier of digital credentials. It is a fork of the Credible credential wallet app developed by [SpruceID](https://www.spruceid.dev/).

<!-- Users can receive, hold, verify and present their credentials -->

## Useful links

- [Trustchain repository (GitHub)](https://github.com/alan-turing-institute/trustchain)
- [Trustchain Mobile repository (GitHub)](https://github.com/alan-turing-institute/trustchain-mobile)
- [Trustchain article](https://arxiv.org/abs/2305.08533)
- [Trustchain wiki](https://github.com/alan-turing-institute/trustchain/wiki)
