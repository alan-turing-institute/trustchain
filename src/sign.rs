use trustchain::controller::TrustchainController;
use trustchain::resolver::Resolver;
use trustchain::subject::TrustchainSubject;

// Binary to resolve a controlled DID, attest to its contents and perform an update
// operation on the controlled DID to add the attestation proof within a service endpoint.
fn main() {
    // ---------------------------------------
    // Update operation for a signing process
    // ---------------------------------------
    // 1. Load controller from passed controlled_did to be signed and controller DID

    // 2. Resolve controlled_did document with Trustchain resolver

    // 3. If Trustchain proof already present, add RemoveService patch

    // 4. Controller performs attestation to Document to generate proof data

    // 5. Proof service is constructed from the proof data and make an AddService patch

    // 6. Create update operation including all patches constructed

    // 7. Either publish the update operation using the publisher or write to JSON file
    //    and publish with `curl`.

    // Create an update request with the signed proof added as a service
}
