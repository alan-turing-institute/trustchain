# Trustchain

Trustchain is a decentralised approach to public key infrastructure, which builds on the W3C standards for [decentralised identifiers (DID)](https://www.w3.org/TR/did-core/) and [verififiable credentials (VC)](https://www.w3.org/TR/did-core/).

These two standards are closely linked: verifying a VC involves resolving the credential issuer's DID document and performing a verification method using material contained in that document. For example, the verification material may be a public key, in which case the verification method is to use the key to verify the issuer's digital signature on the credential.

Trustchain enables the creation of DIDs which are themselves verifiable. Via this mechanism, chains of trustworthy DIDs can be constructed in which **downstream DIDs** (dDIDs) contain an attestation from an entity represented by an **upstream DID** (uDID). It also enables a root DID to be securely established, so that downstream DIDs can be verified by tracing their chain of attestions back to the recognised root.

<center><img src="figs/dDID_schematic.png" width="400px" /></center>

The following links may be of particular interest:
- [Trustchain repo](https://github.com/alan-turing-institute/trustchain)
- [Trustchain preprint](https://arxiv.org/abs/2305.08533)
- [Trustchain wiki](https://github.com/alan-turing-institute/trustchain/wiki)
- [Trustchain FAQ](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain-FAQ)
- [Slides & videos](https://github.com/alan-turing-institute/trustchain/wiki#presentations)
- [Technical notes](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain-Technical-Notes)
