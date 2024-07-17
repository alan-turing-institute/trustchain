# FAQ

Welcome to the Trustchain frequently asked questions (FAQ) page.

### Q: Do we really need a new approach to public key infrastructure? Why not use the existing Web PKI?

In principle, public keys contained in X.509 certificates (and attested to by Certificate Authorities) could be used for the purpose of credential verification. However such a system cannot provide the level of trustworthiness necessary in the context of digital identity.

The existing Web PKI suffers from known vulnerabilities, which have occasionally been exploited in the past. Some of these issues are described in a 2016 memo from the IETF, a review of which can be found [here](https://github.com/alan-turing-institute/trustchain/wiki/Trustchain:-Review-of-Web-PKI).

But the fundamental problem with using the Web PKI for digital identity is the artificial nature of the trust relationships between Certificate Authorities and the entities they certify. They are artificial in the sense that there was no pre-existing relationship. Instead one has been manufactured on request, purely for the purpose of sharing public keys.

As such, it is impossible for relying parties to evaluate the level of trust they should place in an entity simply because they are the subject of an X.509 certificate, or whether that entity is an appropriate authority to issue credentials of a particular kind.

Contrast this to the hierarchical connections in Trustchain, which are digital representations of genuine trust relationships that already existed between recognisable and relatable entities in the physical world.

### Q: What is meant by the term "independently verifiable timestamping"?

*Timestamping* refers to the process of attaching date/time information to a piece of data which serves as a proof that the data existed at that time. *Verifiable timestamping* means that there exists some mechanism by which that proof can be verified.

*Independently verifiable timestamping* means that the mechanism used to verify a timestamp is available to anybody, and does not require any special knowledge or trust in any third party.

For a full explanation of the timestamping process and verification mechanism, see [this technical note](technical-notes.md#independently-verifiable-timestamping).

### Q: Why is independently verifiable timestamping important in Trustchain?

Trustchain builds on the [Identity Overlay Network](https://identity.foundation/ion/) (ION), which itself leverages Bitcoin's proof of work mechanism to publish DID documents with independently verifiable timestamps.

Crucially, the timestamp verification process can be performed by anyone, without requiring any prior knowledge on the part of the verifier (e.g. knowledge of a particular public key).

Verifiable timestamping plays an important role in the design of Trustchain by enabling three core mechanisms:

  1. **Secure and efficient sharing of the root DID**

    All participants in the system must agree on the same root DID which is to act as the root of trust for all downstream DID connections. How should this be achieved?

    The DID itself is typically a long string of base64-encoded characters, making it difficult to transcribe and easy to confuse. Therefore it can only realistically be shared by electronic means, and transcribed by copying & pasting. However this raises the question of how users are to be confident that they have been sent the correct root DID, and not a fraudulent one.

    In Trustchain, verifiable timestamping provides a much simpler and more reliable way to share this vital information. Only the date on which the root DID was published needs to be shared, together with a short 3-character confirmation code (which is a fragment of the corresponding Bitcoin transaction ID).

    A calendar date is short enough, and familiar enough, to be shared via non-digital channels (incuding TV, radio, newspapers, physical notice boards and word of mouth). This means that the process of sharing/publicising the root DID need not depend on any existing public key infrastructure.

  2. **Defence against root DID spoofing**

    Since the data registry used to publish DID information is open and permissionless, there is a risk that an attacker might publish fake (or "spoof") DIDs which, if accepted as valid, could enable them to issue fraudulent credentials.

    The digital signatures on downstream DIDs prevent such an attack, but the root DID is unsigned so a different mechanism is required to avoid spoofing.

    We assume here that the date (and confirmation code) of the root DID are known to all participants, having been shared according to the procedure outlined in point 1 above.

    Under this assumption, the timestamp on the root DID completely neutralises any spoofing attack that takes place before or after the date on which the genuine root transaction was published. Although an attack is theoretically possible on the same date, any attack that takes place outside of that particular 24 hour period is nullified.

    This is good start, but in fact the advantage is much greater. After the 24 hours have elapsed, we can observe all of the DID transactions that were published on the same date as the root, and simply check that no "spoof" transaction exists whose confirmation code matches that of the genuine root transaction. Having done this, we can be certain that no attacker has published, or will ever publish, a fake root transaction that could be confused with our honest one.

  3. **Guaranteed complete DID revocation checks**

    Credential verifiers need to be confident that they have an up-to-date list of any DIDs that have been revoked. Imperfect revocation checking is recognised as a weak point in the Web PKI (see Section 3.2 of this [IETF memo](https://datatracker.ietf.org/doc/html/draft-iab-web-pki-problems-01.txt#section-3-2)), but in Trustchain the fact that all DIDs are verifiably timestamped provides a guarantee that all revocation information, up to the time of the latest available Bitcoin block, is known.

    Bitcoin's chain of proof of work enables anyone to verify that they haven't missed any DID transactions in the middle of the chain. And verifiable timestamping makes it possible to verify that nothing has been missed off the end. One just needs to look at the timestamp of the most recent available block to be certain that all of the DID operations published up to that time have been observed.

    Verifiers can therefore be certain that they have received all revocation notifications up to a given time.

### Q: Isn't Bitcoin wasteful? Does Trustchain contribute to Bitcoin's energy consumption?

The Bitcoin protocol employs the proof of work (PoW) mechanism to achieve consensus across a peer-to-peer network regarding the order of monetary transactions. This enables it to solve the [double-spending problem](https://en.wikipedia.org/wiki/Double-spending) without the need for any central authority. The result is a signal that is unforgeably costly to produce and can be independently verified by anybody.

A similar mechanism can be observed in certain biological systems, a phenomenon known as the [handicap principle](https://en.wikipedia.org/wiki/Handicap_principle). In this context, reliable signalling between individual animals is achieved through the apparent squandering of scarce resources to produce the signal.

Like the handicapping behaviour that demonstrates biological fitness, proof of work may appear wasteful at first glance. However on closer inspection we see that the benefits accruing from the improved reliability of the signal outweigh the cost of the resources consumed in producing it. If this were not the case we would not observe the behaviour in the first place, since it would yield no economic (or biological) advantage.

Trustchain (via the [ION system](https://identity.foundation/ion/)) makes use of the same incorruptible signals generated by Bitcoin's proof of work to endow DID documents and metadata with independently verifiable timestamps, which form the basis of its security model. No new consumption of energy is needed because the work is already being done by the Bitcoin network. This implies a greater overall efficiency, since the same work is being put to greater use.

&nbsp;
