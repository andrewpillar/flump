# flump

flump is a simple content addressable HTTP file server.

* [Quick Start](#quick-start)
* [Security](#security)
* [Limiting Uploads](#limiting-uploads)
* [Hashing Mechanism](#hashing-mechanism)
* [Storage Location](#storage-location)
* [How Files are Stores](#how-files-are-stored)

## Quick Start

Follow the steps below to build flump,

    $ git clone https://github.com/andrewpillar/flump.git
    $ cd flump
    flump $ go build -tags netgo

this will give you a statically linked binary ready to deploy. To run flump
simply invoke the binary,

    $ ./flump
    2006/01/02 15:04:05 INFO  serving on :8080
    2006/01/02 15:04:05 INFO  flump at: http://localhost:8080
    2006/01/02 15:04:05 INFO  using hash mechanism: sha256
    2006/01/02 15:04:05 INFO  storing files at: .

you can then start uploading files to flump like so,

    $ curl -X POST --data-binary @main.go localhost:8080
    {"ref":"sha256-8768128","size":8412,"url":"http://localhost:8080/sha256-e0d7629"}

you can then view the file via the `url` parameter sent in the JSON response.

    $ curl http://localhost:8080/sha256-e0d7629

## Security

By default flump doesn't perform any authentication on `POST` requests sent to
the server. This can be enabled via the `-secret` flag,

    $ ./flump -secret 1a2b3c4d5e6f

this will then expected an `Authorization` header to be sent in each `POST`
request made, otherwise a `403 Forbidden` response is sent back.

    $ curl -X POST -H "Authorization: Bearer 1a2b3c4d5e6f" --data-binary @main.go localhost:8080

flump can aslo be configured to be served over TLS via the `-cert` and `-key`
flags.

    $ ./flump -cert server.crt -key server.key -secret 1a2b3c4d5e6f

## Limiting Uploads

By default flump doesn't put any limit on the size of files that can be
uploaded, this can be set via the `-limit` flag,

    $ ./flump -limit 1000000000

## Hashing Mechanism

The default hashing mechanism used by flump is SHA256, this can be changed via
the `-mech` flag,

    $ ./flump -mech md5

right now flump only supports SHA256 and MD5.

## Storage Location

By default flump will store the uploaded files in the directory where the binary
is invoked. This can be changed via the `-dir` flag,

    $ ./flump -dir /var/lib/flump

## How Files are Stored

As mentioned, flump uses content addressable storage. When a file is uploaded to
flump it will generate a ref of this file which will look something like this,

    <mech>-<hash>

where `<mech>` is the hashing mechanism that was used, and `<hash>` is the hex
encoded hash of the file. A directory will first be created name after the
abbreviated ref, an abbreviated ref is simply the `<mech>` portion of the ref
followed by the first 7 characters of the hex encoded `<hash>`. The tail of
the ref is then used as the name of the file on the filesystem within the
directory.

For example assume we uploaded a file that generated the below complete ref,

    sha256-e0d7629e3c062cbd6947ce75ae66cfb4d8a7103be9d507b9bfb6e5b39544b62c

on disk the directory `sha256-e0d7629` would be created, and the uploaded file
would be stored as `e3c062cbd6947ce75ae66cfb4d8a7103be9d507b9bfb6e5b39544b62c`.

    $ ls
    sha256-e0d7629
    $ ls sha256-e0d7629
    e3c062cbd6947ce75ae66cfb4d8a7103be9d507b9bfb6e5b39544b62c

If the same file is uploaded twice then flump will respond with an error.
