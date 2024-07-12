# User Roles

This section discusses the different types of user role that exist within Trustchain. Throughout the section we will use a concrete example of an individual holding a digital driving license issued by their vehicle driving agency and using this to provide proof of their driving status to a car hire company.

## Credential Holder

A credential holder is an entity that possesses verifiable credentials and has the ability to generate verifiable presentations from them.

Example: someone who possesses a digital driving license, where the digital driving license is the verifiable credential and the persons's ability to verifiably presentation this to verifiers such as a car hire company.

## Credential Verifier

A credential verifier is an entity that can verify verifiable credentials and presentations.

Example: car hire company receives the digital driving license signed by the holder as a verifiable presenation and the car hire company is able to verify both the signature of the holder and the driving license issuer.

## Credential Issuer

DVLA (Vehicle licensing agency)

## dDID Subject

Vehicle licensing agency

## dDID Issuer

Department for Transport

## Root DID Subject

Central govenment

## Summary

The following table summarises how the various user roles are supported by the Trustchain software.

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

&nbsp;
