## Acme Lightweight Client

This project is yet another [_Let's Encrypt_](https://letsencrypt.org) client. It has the following properties.

* The main artifact is a C++ static library.
* Functionality only supports creating and updating certificates using http challenges.
* All code runs 'in process', i.e., no processes are spawned.

#### Building and Installing

Building requires cmake, openssl and curl. On Debian based systems this will install them.

```
apt-get install cmake libssl-dev libcurl4-gnutls-dev
```

On Red Hat based systems this will do it.

```
yum install cmake openssl-devel curl-devel
```

On macOS you'll install prerequisites with your package manager of choice.

To build and install run:

```
cmake .
make
make install
```

To run against the _Let's Encrypt_ staging environment generate your makefiles with this.

```
cmake -D STAGING=ON .
```

#### Let's Encrypt Credentials

To use any _Let's Encrypt_ client you need to sign requests with the private key of a _Let's Encrypt_'s account.
You'll want to keep control of that key in case you ever need to revoke the certificates that you issue. (In addition,
Let's Encrypt [rate limits](https://letsencrypt.org/docs/rate-limits/#:~:text=You%20can%20create%20a%20maximum%20of%2010%20Accounts%20per%20IP,one%20account%20for%20many%20customers) account creation, so you'll normally want to re-use the same account.)

This library uses a private key in PEM format. The [acme-tiny](https://github.com/diafygi/acme-tiny) library has 
[good documentation](https://github.com/diafygi/acme-tiny#step-1-create-a-lets-encrypt-account-private-key-if-you-havent-already) on how to create a new one or convert an existing certbot key to PEM format.

#### Command Line Client

The command line client is run as follows.

```
acme_lw_client <filename of account private key> <domain name> ...
```

Multiple domain names can be on the command line.

The behavior is similar to the official _Let's Encrypt_ client run as follows:

```
certbot certonly --manual -d <domain name>
```

#### Library API

The API of the library is documented in its [header file](lib/acme-lw.h). The command line client [source](main/main.cpp)
provides an example of how it's used.

All methods report errors by throwing std::exception, which will normally be an instance of acme_lw::AcmeException.
Note that this means you should compile your client code and this code with the same compiler and ideally with
the same compiler options.

If your code is in _main.cpp_, something like this will build and link.

```
g++ main.cpp -lacme_lw -lcurl -lcrypto
```

#### Security

The library itself is fairly agnostic about security. It doesn't read or write to disk. If you use the library
you'll need to decide for yourself how you want to protect the account private key and the private key
associated with the certificates issued.

The command line client writes the certificate and private key to disk, readable only by the current user. It
reads the account private key (in PEM format) from disk, so it needs to be readable by the current user.
You'll need to decide whether that's acceptable and if so which user you want to use. (You probably want to
create one solely for this purpose.)

The certificate issued uses a 2,048 bit RSA key.




