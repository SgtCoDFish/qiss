# qiss

qiss is a toy application exploring the integration of post-quantum cryptography into certificate verification during a TLS connection.

It adds a TLS server which embed a post-quantum signature into the cert it generates, and a client which validates the post-quantum signatures in the certs after the regular TLS handshake is complete.

## Security

The techniques used here aren't suitable for public use; they're not fully thought through, need to be rearchitected, and could be entirely wrong. The post-quantum signatures used here don't really assert anything useful.

The certificate extensions used for post-quantum crypto are also entirely arbitrary and unstandardized. Nothing else will (or should) understand them. The final design for post-quantum TLS will almost certainly look nothing like this.

qiss doesn't attempt to use a post-quantum KEM and as such the TLS handshake used here isn't post-quantum; only the signatures on the generated server certificate are post-quantum.

## Running the Example

Every artifact - including the required C library, liboqs - is placed into `bin/`. Everything can be build and controlled through the `Makefile`.

```console
# Run the server (will download and build liboqs first, which will require a C compiler and CMake to be installed)
make runqiss_server

# The server writes bin/ca.crt which has both an ECDSA and post-quantum signature

# Run the client, which loads bin/ca.crt for verification.
make runqiss_client
```
