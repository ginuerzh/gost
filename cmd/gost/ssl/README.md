[//]: <> (https://gist.github.com/fntlnz/cf14feb5a46b2eda428e000157447309)

# Create Root CA (Done once)

## Create Root Key

**Attention:** this is the key used to sign the certificate requests, anyone holding this can sign certificates on your behalf. So keep it in a safe place!

```bash
openssl genrsa -des3 -out rootCA.key 4096
```

If you want a non password protected key just remove the `-des3` option


## Create and self sign the Root Certificate

```bash
openssl req -x509 -new -nodes -key rootCA.key -sha256 -days 1024 -out rootCA.crt
```

Here we used our root key to create the root certificate that needs to be distributed in all the computers that have to trust us.


# Create a certificate (Done for each server)

This procedure needs to be followed for each server/appliance that needs a trusted certificate from our CA

## Create the certificate key

```
openssl genrsa -out mydomain.com.key 2048
```

## Create the signing request

**Important:** Please mind that while creating the signign request is important to specify the `Common Name` providing the IP address or URL for the service, otherwise the certificate
cannot be verified

```
openssl req -new -key mydomain.com.key -out mydomain.com.csr
```

## Generate the certificate using the `mydomain` csr and key along with the CA Root key

```
openssl x509 -req -in mydomain.com.csr -CA rootCA.crt -CAkey rootCA.key -CAcreateserial -out mydomain.com.crt -days 500 -sha256
```
