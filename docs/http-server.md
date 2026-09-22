# HTTP Server

Trustchain includes a built-in HTTP server that can be used to issue and verify digital credentials via an HTTP API. The server can also respond to requests made by the Trustchain Mobile app.

!!! info "Prerequisites"

    To use the Trustchain HTTP server, first make sure you have followed the installation and configuration instructions on the [Getting Started](getting-started.md) page.

    Your ION node will also need to be up and running, either locally or on a remote machine to which you are connected via SSH with port forwarding. Instructions for running ION, and setting up port forwarding, can be found [here](ion.md#running-ion).

## Installation

To install the Trustchain HTTP server, run:
```console
cargo install --path "$TRUSTCHAIN_REPO"/crates/trustchain-http
```

## Configuration

Before starting the HTTP server some configuation parameters will need to be set. Open the Trustchain [configuration file](getting-started.md#trustchain-configuration-file) for editing:
```console
nano $TRUSTCHAIN_CONFIG
```

Under the section headed `[http]`, add or edit the following configuration parameters:

- Set the `root_event_time` parameter to the integer root DID timestamp for your network (in Unix Time).
- Set the `host_display` parameter to the fully qualified domain name of your Trustchain HTTP server.
- Set the `host` parameter to the host address for the server. If you want the server to be accessible only on a local network, set this to `"127.0.0.1"` (localhost). If you want the server to be accessible from the Internet, set it to `"0.0.0.0"`. In this case, ensure both your router and server are protected by a properly configured firewall.
- Set the `port` parameter to the port number on which your server will listen for HTTP requests.
- Set the `https` parameter to either `true` or `false`, depending on whether your server will use TLS for encrypted communications.
- If `https` is set to `true`, set the  `https_path` parameter to the directory containing the certificate and key necessary for accepting HTTPS connections. See the section on [HTTPS configuration](#https-configuration) for more details.
- Set the `ion_host` parameter to the host name of your ION instance. If ION is running on the local machine, set this to the loopback address `"127.0.0.1"`.
- Set the `ion_port` parameter to the port number of your ION instance. By default, ION listens on port `3000`.
- If you intend to use your server for credential verification and/or for dDID attestation (via the Trustchain challenge-response protocol), and you already have your own DID for this purpose, set it as the `server_did` parameter. If the server is only intended to respond to requests from the Trustchain Mobile app, e.g. for [issuing verifiable credentials](#credential-issuance), this parameter is not required and can be omitted.

!!! example "Example HTTP server configuration"

    After completing the above steps, the `[http]` section of `trustchain_config.toml` should look similar to the following example:

    ```bash
    [http]
    root_event_time = 1769521645
    host_display = "<YOUR_SERVER_HOSTNAME>"
    port = 443
    https = true
    https_path = "~/.trustchain/http/self_signed_certs"
    host = "0.0.0.0"
    ion_host = "127.0.0.1"
    ion_port = 3000
    server_did = "<YOUR_SERVER_DID>"
    ```

### Network configuration

To make your Trustchain HTTP server reachable from the public Internet you will need to configure your local network to allow connections to the port given in the Trustchain [configuration file](getting-started.md#trustchain-configuration-file), and to route them to your Trustchain node.

If your Trustchain node is running on a virtual machine (VM) in the cloud, navigate to your cloud provider's web portal and open the network settings page for the VM. Then create an "inbound port rule" to allow incoming traffic to the relevant port.

If your node is running on a computer in your local network, the network configuration steps are as follows:

- On your router, configure the firewall to allow connections to the port configured for the Trustchain server, and configure port forwarding (for the same port) to the IP address of your Trustchain node on the local network. To enable this, you may want to assign a static local IP address to your Trustchain node.
- If there is a firewall running on your Trustchain node, ensure it is configured to allow inbound connections to the relevant port.

### HTTPS configuration

It is strongly advisable to configure your Trustchain HTTP server to use TLS (Transport Layer Security) for encrypted communictions via HTTPS. This is done by setting the `https` config parameter to `true` and the `port` parameter to `443`, which is the default HTTPS port number.

!!! info "HTTPS is required to support Trustchain Mobile"

    The Trustchain HTTP server is designed to handle requests from the Trustchain Mobile app, for operations such as the issuance and verification of [Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/).

    If you intend to use the HTTP server for this purpose, it is essential that you configure it with HTTPS support. The Trustchain Mobile app will refuse to connect to a server that does not have a valid TLS certificate.

To support HTTPS, you will need a TLS certificate and associated cryptographic keys.

If you do not already have a TLS certificate, you can obtain one by using a free and open source service called [Certbot](https://certbot.eff.org/). Certbot is a software tool for automatically generating [Let's Encrypt](https://letsencrypt.org/) certificates for web servers to enable HTTPS, which is precisely what is needed here.

Follow the steps in the [Certbot setup instructions](https://certbot.eff.org/instructions?ws=other&os=ubuntubionic) to generate a TLS certificate.

At the end of Step 6, you should see output similar to the following:
```{ .text .no-copy }
Successfully received certificate.
Certificate is saved at: /etc/letsencrypt/live/trustchain.example.com/fullchain.pem
Key is saved at:         /etc/letsencrypt/live/trustchain.example.com/privkey.pem
This certificate expires on 2024-02-25.
These files will be updated when the certificate renews.
Certbot has set up a scheduled task to automatically renew this certificate in the background.
```

Step 7 of the Certbot instructions requires you to install your new TLS certificate. To do this:

- make a new directory to store the certificate:
```console
mkdir -p "$TRUSTCHAIN_DATA"/http/self_signed_certs
```
- copy the certificate file `fullchain.pem` and the key file `privkey.pem` from the locations given in the output from Step 6 (above), to the new directory, e.g.:
```console
sudo cp /etc/letsencrypt/live/trustchain.example.com/fullchain.pem "$TRUSTCHAIN_DATA"/http/self_signed_certs
sudo cp /etc/letsencrypt/live/trustchain.example.com/privkey.pem "$TRUSTCHAIN_DATA"/http/self_signed_certs
```
- change the ownership of those files so they are owned by the user and group that will run the Trustchain server (replace `<USER>` and `<GROUP>` in the following commands):
```console
sudo chown <USER>:<GROUP> "$TRUSTCHAIN_DATA"/http/self_signed_certs/fullchain.pem
sudo chown <USER>:<GROUP> "$TRUSTCHAIN_DATA"/http/self_signed_certs/privkey.pem
```
- create symbolic links to the certificate and key files:
```console
ln -s "$TRUSTCHAIN_DATA"/http/self_signed_certs/fullchain.pem "$TRUSTCHAIN_DATA"/http/self_signed_certs/cert.pem
ln -s "$TRUSTCHAIN_DATA"/http/self_signed_certs/privkey.pem "$TRUSTCHAIN_DATA"/http/self_signed_certs/key.pem
```

!!! warning "Running the Trustchain HTTP server on port 443"

    By default, elevated privileges are required when binding a process to port 443. Therefore, if you have configured the HTTP server to listen on port 443, you will need to run the following command (once) to allow a non-root user to start the server:
    ```console
    sudo setcap CAP_NET_BIND_SERVICE=+eip $HOME/.cargo/bin/trustchain-http
    ```

## Running the HTTP server

Open a new Terminal window and invoke the Trustchain HTTP server with the following command:
```console
trustchain-http
```

The server will listen on the port specified in the `trustchain_config.toml` file. Server log messages will be printed to this terminal window, so you will see a new message whenever the server responds to a request.

## Credential Issuance

The Trustchain HTTP server can be used to issue [verifiable credentials](usage.md#credential-signing) on behalf of a published DID, via its built-in API. This is done by defining one or more *credential offers* in advance, which the server then makes available for prospective credential holders to redeem.

This process must be carried out by the [credential issuer](roles.md#credential-issuer), that is, the legal entity who attests to the information asserted by the credential and whose DID will appear in its `issuer` field.

!!! info "Prerequisites"

    The Trustchain HTTP server must be installed and configured as described [above](#installation). Additional configuration required for issuing credentials will be explained in this section.

    The DID for credential issuer must already have been published, by following the [DID Issuance](usage.md#did-issuance) process.

    The private key belonging to the issuing entity must be accessible from the running HTTP server instance, so it can be used to sign each credential before it is issued. The key must be found under the `key_manager` directory inside the [Trustchain data directory](getting-started.md#trustchain-data-directory). This is the location in which keys are stored when a [new DID is created](usage.md#create-the-did) using the Trustchain CLI.

!!! tip "Trustchain Mobile credential wallet app"

    Trustchain Mobile is a credential wallet app designed to interact with the Trustchain HTTP server via the credential issuance API described in this section. Note: to support the app, the server must be [configured for HTTPS](#https-configuration).

    A demo version of the app can be downloaded using the QR code displayed below, or you can build the app from its [source code](https://github.com/alan-turing-institute/trustchain-mobile). In either case, you will need to turn on "Developer options" on your mobile device to allow the installation to proceed.

    Once installed, follow these steps to get started.

      - On first use of the app, note down the 12-word passphrase and generate your own DID.
      - In the Settings page:
        - set the Trustchain endpoint (URL) to the address of your Trustchain server,
        - then set the root event date for your network.
      - Use the app's QR code scanner to scan a credential issuance QR code generated by the server (as explained below).
      - Follow the on-screen prompts to accept the credential offer and add it to your wallet.
      - Any credential in the wallet can be presented as QR code, which can be verified by any other Trustchain Mobile user.

    **Install Trustchain Mobile (demo version):**

    ![Install Trustchain Mobile](assets/install-trustchain-mobile.png){: style="height:120px"}

#### Credential offer cache

Credential offers are defined by adding entries to a JSON file located at:
```sh
$TRUSTCHAIN_DATA/credentials/offers/cache.json
```

This file is read once, when the Trustchain HTTP server starts up. If it does not exist, the server will start with no credential offers available.

!!! warning "Note: The `offers` directory is not created automatically"

    Unlike some other Trustchain data directories, `$TRUSTCHAIN_DATA/credentials/offers/` is not created for you. If it does not already exist, create it before adding the cache file:
    ```console
    mkdir -p "$TRUSTCHAIN_DATA"/credentials/offers
    ```

Using a text editor, create (or edit) the `cache.json` file so that it contains a single JSON object. Each key in this object is a unique identifier for one credential offer, and each value is itself an object with two fields:

| <div style="width:5.8em">Field</div> | Description |
| ------------ | ----------------- |
| `did`        | The DID of the credential issuer. This DID must already be published, with its signing key available in the [key manager](usage.md#create-the-did) folder on this machine. |
| `credential` | A template for the credential to be issued, in [W3C Verifiable Credential](https://www.w3.org/TR/vc-data-model-2.0/) JSON-LD format. |

You do not need to include `issuer`, `issuanceDate` or `id` fields inside the credential template: these are populated automatically by the server. The `id` field is a sub-field of `credentialSubject` and contains the DID of the credential subject, which is uploaded to the server during the issuance process.

!!! tip "Tip: Generating a unique identifier"

    Any unique string can be used as the key for a credential offer, but a [UUID](https://en.wikipedia.org/wiki/Universally_unique_identifier) is recommended. To generate one, run:
    ```console
    uuidgen
    ```

!!! example "Example: credential offer cache"

    The following `cache.json` file defines two offers, both issued by the same DID: a Bachelor of Arts degree credential, and a Master of Science degree credential.
    ```json
    {
      "7426a2e8-f932-11ed-968a-4bb02079f142": {
        "did": "did:ion:test:EiDz95rNCN2Iji3qAsySSXT8oHBEtrRqH55sH4wqEELF9g",
        "credential": {
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
          ],
          "type": ["VerifiableCredential"],
          "credentialSubject": {
            "givenName": "John",
            "familyName": "Sims",
            "degree": {
              "type": "BachelorDegree",
              "name": "Bachelor of Arts",
              "college": "University of Oxbridge"
            }
          }
        }
      },
      "481935de-f93d-11ed-a309-d7ec1d02e89c": {
        "did": "did:ion:test:EiDz95rNCN2Iji3qAsySSXT8oHBEtrRqH55sH4wqEELF9g",
        "credential": {
          "@context": [
            "https://www.w3.org/2018/credentials/v1",
            "https://www.w3.org/2018/credentials/examples/v1"
          ],
          "type": ["VerifiableCredential"],
          "credentialSubject": {
            "givenName": "Jane",
            "familyName": "Smith",
            "degree": {
              "type": "MastersDegree",
              "name": "Master of Science",
              "college": "University of Oxbridge"
            }
          }
        }
      }
    }
    ```

!!! warning "Note: Restart required after editing the cache"

    The credential offer cache is only read when the Trustchain HTTP server starts up. After creating or editing `cache.json`, you must (re)start the server for your changes to take effect.

#### Serving a credential offer

Once an offer is present in the cache, it can be issued via the following endpoints, where `<KEY>` is the key used to identify the credential template in `cache.json`:

| <div style="width:9em">Endpoint</div> | Method | Description |
| ----------------- | ------ | ----------------- |
| `/issuer/<KEY>`     | GET    | Returns an HTML page displaying a QR code for the offer, suitable for scanning with the Trustchain Mobile app. |
| `/vc/issuer/<KEY>`  | GET    | Returns a JSON preview of the credential to be issued, valid for 60 minutes. |
| `/vc/issuer/<KEY>`  | POST   | Given the subject's DID, returns the final, signed Verifiable Credential. |

To offer the credential, share a link of the form:
```sh
https://<HOST_DISPLAY>:<PORT>/issuer/<KEY>
```
replacing `<HOST_DISPLAY>` and `<PORT>` with the [`host_display` and `port`](#configuration) values from your Trustchain configuration file.

Opening this link displays a QR code that can be scanned using the Trustchain Mobile app to redeem the offer. The QR code encodes the issuer's DID, which the app resolves to confirm its validity and to obtain the server's credential issuance endpoint (URL), before connecting to it.

The two steps performed by the app can also be carried out from the command line. First, retrieve a preview of the credential on offer:
```console
curl https://<HOST_DISPLAY>:<PORT>/vc/issuer/<KEY>
```

Then, submit the subject's DID to receive the signed credential:
```console
curl -X POST https://<HOST_DISPLAY>:<PORT>/vc/issuer/<KEY> \
    -H "Content-Type: application/json" \
    -d '{"subject_id": "<SUBJECT_DID>"}'
```

The response contains the complete Verifiable Credential, signed by the issuer.

Credential offers are not consumed when redeemed. The same offer can be issued to multiple subjects, or issued more than once to the same subject, until it is removed from `cache.json` and the server is restarted.

!!! warning "Practical credential issuance"

    The issuance process described above, and built into the Trustchain HTTP server by default, is sufficient to demonstrate how credentials offers can be made and redeemed by a user of the Trustchain Mobile app. However it is only illustrative.
    
    The credential offers, given in the example above, contain hard-coded attributes (such as the subject's name) which in practice would need to be inserted at the time of issuance.

    Also, before issuing a credential the prospective holder would need to authenticate themself to the server.

    These important practicalities are application-specific and will depend on the relationship between credential issuer and subject. As such, the example above is intended as an illustration of how the Trustchain server can be incorporated into the credential issuance process, not as a complete practical guide.


??? info "RSS (Redactable Signature Scheme) credentials"

    RSS signatures allow the holder to redact information when presenting a credential, so that only only certain fields are disclosed to the verifier. This is a privacy feature included in Trustchain but is not part of the Verifiable Credentials standard.

    Corresponding `_rss` endpoints are available (`/issuer_rss/<KEY>`, `/vc_rss/issuer/<KEY>`) for the issuance of RSS credentials. Credentials issued via these endpoints are signed using an RSS key contained in the issuer's DID document, instead of their default signing key. 
    
    Note, however, that a single RSS key is around 40 kB in size, which is too large to fit in a standard ION DID document, and therefore a non-standard DID issuance mechanism is required to support this feature.

## Credential Verification

!!! tip "Credential verification via the Trustchain Mobile app"

    A convenient method for verifying credentials is built into the Trustchain Mobile app. 
    
    When viewing a credential in the wallet app, the holder can hit the share button to generate a verifiable presentation in the form of a QR code. This presentation contains all of the information in the credential, plus a signature from the subject (i.e. the holder) and a timestamp generated at the time of sharing. This signature proves that the current holder of the credential is indeed the authentic subject, making fraudulent sharing impractical.

    The verifier, using the same app on a different device, then scans the QR code to read and verify the presentation. This process is automatic, and includes verification of the issuer's DID and signature on the credential, as well as the holder's signature and the timestamp. Any presentation whose timestamp is more than 15 minutes old is flagged as "stale".


The Trustchain HTTP server can also verify credentials and presentations submitted to it via its HTTP API. This works in a similar way to credential issuance: one or more *presentation requests* are defined in advance, and these are served to holders who wish to present a credential for verification.

This process must be carried out by the [credential verifier](roles.md#credential-verifier).

!!! info "Prerequisites"

    The Trustchain HTTP server must be running, with the `root_event_time` [configuration parameter](#configuration) set. See [Running the HTTP server](#running-the-http-server) above.

    To generate a QR code via the `/verifier` endpoint (see below), the `server_did` [configuration parameter](#configuration) must also be set.

#### Presentation request cache

Presentation requests are defined by adding entries to a JSON file located at:
```sh
$TRUSTCHAIN_DATA/presentations/requests/cache.json
```

This file is read once, when the Trustchain HTTP server starts up, in the same way as the [credential offer cache](#credential-offer-cache) used for issuance. As with that cache, `$TRUSTCHAIN_DATA/presentations/requests/` is not created automatically:
```console
mkdir -p "$TRUSTCHAIN_DATA"/presentations/requests
```

Each entry is a JSON object, keyed by a unique identifier, conforming to the [Verifiable Presentation Request](https://w3c-ccg.github.io/vp-request-spec/) specification. In particular, it should contain a `challenge` for the holder to sign, and a `domain` identifying the verifier.

!!! example "Example: presentation request cache"

    ```json
    {
      "b9519df2-35c1-11ee-8314-7f66e4585b4f": {
        "type": "VerifiablePresentationRequest",
        "query": [
          {
            "type": "QueryByExample",
            "credentialQuery": {
              "reason": "Request credential",
              "example": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1"
                ],
                "type": "VerifiableCredential"
              }
            }
          }
        ],
        "challenge": "a877fb0a-11dd-11ee-9df7-9be7abdeee2d",
        "domain": "https://example.com"
      }
    }
    ```

!!! warning "Note: Restart required after editing the cache"

    Like the credential offer cache, the presentation request cache is only read when the Trustchain HTTP server starts up. After creating or editing `cache.json`, you must (re)start the server for your changes to take effect.

#### Serving a presentation request

Once a request is present in the cache, it can be used by a holder via the following endpoints, where `<KEY>` is the request's key from `cache.json`:

| <div style="width:10em">Endpoint</div> | Method | Description |
| ------------------- | ------ | ----------------- |
| `/verifier`          | GET    | Returns an HTML page displaying a QR code, suitable for scanning with the Trustchain Mobile app. |
| `/vc/verifier/<KEY>`  | GET    | Returns the presentation request JSON (including its `challenge` and `domain`). |
| `/vc/verifier/<KEY>`  | POST   | Accepts a credential or presentation from the holder, verifies it, and returns the result. |

!!! warning "Note: The QR code always serves one arbitrary request"

    Unlike credential issuance, where each offer has its own link, `/verifier` always generates a QR code for a single presentation request, chosen arbitrarily from the cache. If you need to issue several distinct presentation requests at once, share each request's `/vc/verifier/<KEY>` link directly instead of relying on the `/verifier` QR code.

To request a credential from a holder, share a link of the form:
```sh
https://<HOST_DISPLAY>:<PORT>/verifier
```
replacing `<HOST_DISPLAY>` and `<PORT>` with the [`host_display` and `port`](#configuration) values from your Trustchain configuration file. As with credential issuance, opening this link displays a QR code that can be scanned using the Trustchain Mobile app. The QR code encodes the verifier's DID, which the app resolves to confirm its validity and to obtain the verification endpoint (URL).

To submit a credential for verification directly via the command line, send a `POST` request containing a JSON body of the following form to `/vc/verifier/<KEY>`:
```console
curl -X POST https://<HOST_DISPLAY>:<PORT>/vc/verifier/<KEY> \
    -H "Content-Type: application/json" \
    -d '{
      "presentationOrCredential": { "credential": <CREDENTIAL> },
      "rootEventTime": <ROOT_EVENT_TIME>
    }'
```
Similarly, to submit a full Verifiable Presentation, replace `"credential": <CREDENTIAL>` with `"presentation": <PRESENTATION>` in the above command.

!!! info "Note: `rootEventTime` in the request body is not used for verification"

    The request body must include a `rootEventTime` field to satisfy the JSON schema, but the server always verifies against its own configured [`root_event_time`](#configuration) parameter, not the value supplied by the caller.

On success, the server responds with `200 OK` and the message `Credential received and verified!` (or `Presentation received and verified!`). On failure, it responds with a JSON body of the form `{"error": "<message>"}`.

#### Verification process

Whichever submission mechanism is used, the Trustchain HTTP server performs the same checks as the CLI's [`vc verify`](usage.md#credential-verification) command:

 1. Verify each credential's own cryptographic signature (Linked Data Proof), using the public key found in the DID document of its `issuer`.
 2. Resolve each issuer's DID and verify its full chain back to the root DID, checking the root's timestamp against the configured `root_event_time`.

If a full presentation is submitted (rather than a bare credential), the holder's own signature over the presentation is also verified, using the signing key referenced in its proof.

!!! warning "Note: The presentation's `challenge` and `domain` are not checked"

    Although each presentation request includes a `challenge` and `domain`, as set out in the Verifiable Presentation Request [specification](https://w3c-ccg.github.io/vp-request-spec/), the current implementation does not verify that a submitted presentation's proof actually contains the matching values. This means the server does not yet enforce that a presentation was created specifically in response to its request, only that it carries a valid signature from its holder.

&nbsp;
