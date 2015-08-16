# cert-generator
Useful for things like etcd and docker that use client TLS to authenticate.


This will generate a CA cert, a Server cert and a Client cert.

It will also sign your server and client certs with the CA.

It will also set proper EKU of Client and Server auth on the generated keys.
