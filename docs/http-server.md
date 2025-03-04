# HTTP Server

Trustchain includes a built-in HTTP server that can be used to issue and verify digital credentials via an HTTP API. The server can also respond to requests made by the Trustchain Mobile app.

!!! info "Prerequisites"

    To use the Trustchain HTTP server, first make sure that you have followed the installation and configuration instructions on the [Getting Started](getting-started.md) page.

    Your ION node will also need to be up and running, either locally or on a remote machine to which you are connected via SSH and with port forwarding. Instructions for restarting ION, and setting up port forwarding, can be found [here](ion.md#running-ion).

## Installation

To install the Trustchain HTTP server, run:
```console
$ cargo install --path "$TRUSTCHAIN_REPO"/crates/trustchain-http
```

## Configuration

Before starting the HTTP server some configuation parameters will need to be set. Execute the following command to open the Trustchain configuration file `trustchain_config.toml` for editing:
```console
$ nano $TRUSTCHAIN_CONFIG
```

Under the section headed `[http]`, add or edit the following configuration parameters:

- Set the `root_event_time` parameter to the integer root DID timestamp for your network (in Unix Time).
- Set the `host_display` parameter to the fully qualified domain name of your Trustchain HTTP server.
- Set the `port` parameter to the port number on which your server will listen for HTTP requests.
- Set the `https` parameter to either `true` or `false`, depending on whether your server will use TLS for encrypted communications.
- If `https` is set to `true`, set the  `https_path` parameter to the directory containing the certificate and key necessary for accepting HTTPS connections. See the section on [HTTPS configuration](#https-configuration) for more details.
- Set the `ion_host` parameter to the host name of your ION instance. If ION is running on the local machine, set this to the loopback address `"127.0.0.1"`.
- Set the `ion_port` parameter to the port number of your ION instance. By default, ION listens on port `3000`.
- If you intend to act as an issuer of digital credentials and you already have you own DID for this purpose, set it as the `server_did` parameter.

!!! example "Example HTTP server configuration"

    After completing the above steps, the `[http]` section of `trustchain_config.toml` should look similar to the following example:
    ```bash
    [http]
    root_event_time = 1697213008
    host_display = "https://trustchain.example.com"
    port = 443
    https = true
    https_path = "~/.trustchain/http/self_signed_certs"
    ion_host = "127.0.0.1"
    ion_port = 3000
    server_did = "did:ion:test:EiB4S2znMhXFMxLLuI6dSrcfn4uF1MLFGvMYTwRPRH_-eQ"
    ```

### HTTPS configuration

It is strongly advisable to configure your Trustchain HTTP server to use TLS (Transport Layer Security) for encrypted communictions via HTTPS. This is done by setting the `https` config parameter to `true` and the `port` parameter to `443`, which is the default HTTPS port number.

In this case, you will need a TLS certificate and associated cryptographic keys.

If you do not already have a TLS certificate, you can obtain one by using a free and open source service called [Certbot](https://certbot.eff.org/). Certbot is a software tool for automatically generating [Let's Encrypt](https://letsencrypt.org/) certificates for web servers to enable HTTPS, which is precisely what is needed here.

Follow the steps in the [Certbot setup instructions](https://certbot.eff.org/instructions?ws=other&os=ubuntubionic) to generate a TLS certificate.

At the end of Step 6, you should see output similar to the following:
```
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
$ mkdir "$TRUSTCHAIN_CONFIG"/http/self_signed_certs
```
- copy the certificate file `fullchain.pem` and the key file `privkey.pem` from the locations given in the output from Step 6 (above), to the new directory, e.g.:
```console
$ sudo cp /etc/letsencrypt/live/trustchain.example.com/fullchain.pem "$TRUSTCHAIN_CONFIG"/http/self_signed_certs
$ sudo cp /etc/letsencrypt/live/trustchain.example.com/privkey.pem "$TRUSTCHAIN_CONFIG"/http/self_signed_certs
```
- change the ownership of those files so they are owned by the user and group that will run the Trustchain server (replace `<USER>` and `<GROUP>` in the following commands):
```console
$ sudo chown <USER>:<GROUP> "$TRUSTCHAIN_CONFIG"/http/self_signed_certs/fullchain.pem
$ sudo chown <USER>:<GROUP> "$TRUSTCHAIN_CONFIG"/http/self_signed_certs/privkey.pem
```
- create symbolic links to the certificate and key files:
```console
$ ln -s "$TRUSTCHAIN_CONFIG"/http/self_signed_certs/fullchain.pem "$TRUSTCHAIN_CONFIG"/http/self_signed_certs/cert.pem
$ ln -s "$TRUSTCHAIN_CONFIG"/http/self_signed_certs/privkey.pem "$TRUSTCHAIN_CONFIG"/http/self_signed_certs/key.pem
```

!!! warning "Running the Trustchain HTTP server on port 443"

    By default, elevated privileges are required when binding a process to port 443. Therefore, if you have configured the HTTP server to listen on port 443, you will need to run the following command (once) to allow a non-root user to start the server:
    ```console
    $ sudo setcap CAP_NET_BIND_SERVICE=+eip $HOME/.cargo/bin/trustchain-http
    ```

### Network configuration

To make your Trustchain HTTP server reachable from the public Internet you will need to configure your local network to allow connections to the port given in the `trustchain_config.toml` file, and to route them to your Trustchain node.

If your Trustchain node is running on a virtual machine (VM) in the cloud, navigate to your cloud provider's web portal and open the network settings page for the VM. Then create an "inbound port rule" to allow incoming traffic to the relevant port.

If your node is running on a computer in your local network, the network configuration steps are as follows:

- On your router, configure the firewall to allow connections to the port configured for the Trustchain server,
- On your router, configure port forwarding (for the same port) to the IP address of your Trustchain node on the local network. To enable this, you may want to assign a static local IP address to your Trustchain node.
- If there is a firewall running on your Trustchain node, ensure it is configured to allow connections to the relevant port.

## Running the HTTP server

Open a new Terminal window and invoke the Trustchain HTTP server with the following command:
```console
$ trustchain-http
```

The server will listen on the port specified in the `trustchain_config.toml` file. Server log messages will be printed to this terminal window, so you will see a new message whenever the server responds to a request.

&nbsp;
