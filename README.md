# rustserve-platform

# Warning

This is very much a WIP and should not be relied upon whatsoever right now.

# Getting started

* generate the certificates necessary for mtls
  * do so by running `build-a-pki.sh` and moving the output artifacts into a
    directory called `service_name_mtls` where `service_name` is the name of the
    service thats serving routes.  That is if you have a binary serving multiple
    service controllers, your binary has a single service name and you would use
    `service_name_mtls` for your service and when deployed it would look up its
    service certificates in the expected place on the deployed instance.
* `export CA_CERT_BUNDLE=/etc/ssl/certs/ca-bundle.crt`
* `export CERTIFICATE_ROOT=$(pwd)`
