# User Roles

This page discusses the different roles that exist within a Trustchain user group. A user's role will determine which components of the Trustchain software suite they make use of, and this relationship is summarised the following table:

&nbsp;

<div class="center-table" markdown>

| Role | Trustchain Mobile | Trustchain using Docker | Trustchain full installation |
| ---- | :---------------: | :---------------------: | :--------------------------: |
| Credential Holder   | :fontawesome-solid-circle-check:{ .check } | :fontawesome-solid-circle-xmark:{ .xmark } | :fontawesome-solid-circle-xmark:{ .xmark } |
| Credential Verifier | :fontawesome-solid-circle-check:{ .check } | :fontawesome-solid-circle-check:{ .check } | :fontawesome-solid-circle-check:{ .check } |
| Credential Issuer   | :fontawesome-solid-circle-xmark:{ .xmark } | :fontawesome-solid-circle-check:{ .check } | :fontawesome-solid-circle-check:{ .check } |
| dDID Subject        | :fontawesome-solid-circle-xmark:{ .xmark } | :fontawesome-solid-circle-check:{ .check } | :fontawesome-solid-circle-check:{ .check } |
| dDID Issuer         | :fontawesome-solid-circle-xmark:{ .xmark } | :fontawesome-solid-circle-xmark:{ .xmark } | :fontawesome-solid-circle-check:{ .check } |
| Root DID Subject    | :fontawesome-solid-circle-xmark:{ .xmark } | :fontawesome-solid-circle-xmark:{ .xmark } | :fontawesome-solid-circle-check:{ .check } |

</div>

## User Roles Example

To illustrate the various user roles, we use the concrete example of an individual holding a **digital driver's licence** issued by a national vehicle licensing agency. The holder of this credential will use it to provide proof of their registered driver status to a car rental company.

## Credential Holder

A credential holder is an individual possessing one or more verifiable credentials (VCs) in which they are the subject. Holders have the ability to generate verifiable presentations (VPs) from their credentials.

!!! example "Example: Digital driver's licence holder"

    An individual holding a digital driver's license in a credential wallet on their mobile device is a **credential holder**.

    The Trustchain Mobile app includes a credential wallet which enables the individual to receive the credential from a verified URL, confirm the validity of the received credential, store the credential and subsequently present it to a third party, such as a car hire company.

## Credential Verifier

A credential verifier is an individual or legal entity that can verify presentations shared by a credential holder (and derived from one or more of their credentials).

This involves retrieving the credential issuer's public key via the Trustchain verifiable public key infrastructure, and then using it to verify the issuer's signature on the presentation. The credential verifier also verifies the holder's signature on the presentation, and its timestamp, thereby confirming that the presentation was not generated in advance by another party in possession of the holder's private key.

To verify the holder's signature, the credential verifier must also have access to the holder's public key, which can be shared either via the Trustchain PKI or by using the `did:key` method, in which the holder's public key is embedded inside their DID identifier.

!!! example "Example: Car hire company"

    Before authorising a vehicle rental, a car hire company must establish that their client is in possession of a valid driving licence. They must also confirm certain information about the driver, such as their full name, driver number and country of residence.

    The credential holder generates a verifiable presentation containing this information and shares it with the car hire company, either by uploading it to their server or by generating a QR code for direct sharing between devices.

    Having received the presentation, an employee of the rental company is able to verify the signatures on it using either the Trustchain Mobile app or a full Trustchain installation if available. This employee is a **credential verifier**. The presentation will also contain the personal details shared by the holder, which are covered by the issuer's signature and therefore known to be genuine.

## Credential Issuer

A credential issuer is a legal entity that issues a verifiable credential to an individual to which they attach their signature, thereby attesting to the validity of the information contained in the credential.

Credential issuers must run a full Trustchain node. By running the built-in Trustchain HTTP server they can expose a service endpoint (URL) for issuing credentials and/or responding to requests from the Trustchain Mobile client.

!!! example "Example: Driver and Vehicle Licensing Agency"

    The government agency responsible for issuing driver's licences is the **credential issuer**.

## dDID Subject

A downstream DID (dDID) subject is a legal entity or individual whose DID appears in the `id` field of a DID, which itself bears an attestation (signatuare) from an upstream entity.

Downstream DID subjects must run a full Trustchain node in order to participate in the challenge-response process through which a dDID is issued.

!!! example "Example: Driver and Vehicle Licensing Agency"

    In our example, the Driver and Vehicle Licensing Agency is both a credential issuer and a **dDID subject**. Indeed, it is the agency's status as a dDID subject that makes it possible for it to issue credentials that can be subsequently verified by a credential verifier.

## dDID Issuer

A downstream DID (dDID) issuer is a legal entity or individual whose DID appears in the `controller` field of a downstream DID. A dDID issuer is therefore necessarily also an upstream DID (uDID) subject.

Downstream DID issuers must run a full Trustchain node in order to participate in the challenge-response process through which a dDID is issued.

!!! example "Example: Government Department for Transport"

    Suppose that the Driver and Vehicle Licensing Agency is overseen by the government's Department for Transport. In that case, the agency's dDID would be signed by that government department, which itself is represented by a uDID. This makes the Department for Transport a **dDID issuer**.


## Root DID Subject

The root DID subject is the legal entity (or group of entities) whose DID appears in the `id` field of the root DID.

The root DID sits at the top of the hierarchical DID structure. Therefore the root DID subject is not a downstream DID subject and there is no signature of attestation on the root DID document. Instead, the contents of the root DID document are verified by checking that it was published on a particular date, as explained in the [FAQs](faq.md#q-why-is-independently-verifiable-timestamping-important-in-trustchain).

!!! example "Example: Central government"

    In a national digital ID system the central government would be a natural choice for **root DID subject**. They would act as the first dDID issuer and would issue a dDID to each government department, including the Department for Transport.

&nbsp;
