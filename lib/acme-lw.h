#pragma once

#include "acme-exception.h"

#include <ctime>
#include <list>
#include <memory>

namespace acme_lw
{

struct Certificate
{
    std::string fullchain;
    std::string privkey;

    // Note that neither of the 'Expiry' calls below require 'privkey'
    // to be set; they only rely on 'fullchain'.

    /**
        Returns the number of seconds since 1970, i.e., epoch time.

        Due to openssl quirkiness on older versions (< 1.1.1?) there 
        might be a little drift from a strictly accurate result, but 
        it will be close enough for the purpose of determining 
        whether the certificate needs to be renewed.
    */
    ::time_t getExpiry() const;

    /**
        Returns the 'Not After' result that openssl would display if
        running the following command.

            openssl x509 -noout -in fullchain.pem -text

        For example:

            May  6 21:15:03 2026 GMT
    */
    std::string getExpiryDisplay() const;
};

struct AcmeClientImpl;

/**
 * Each AcmeClient assumes access from a single thread, but different
 * instances can be instantiated in different threads.
 */
class AcmeClient
{
public:
    /**
        The signingKey is the Acme account private key used to sign
        requests to the acme CA, in pem format.
    */
    AcmeClient(const std::string& signingKey);

    ~AcmeClient();

    /**
        The implementation of this function allows Let's Encrypt to
        verify that the requestor has control of the domain name.

        [HTTP] The callback may be called once for each domain name in the
        'issueCertificate' call. The callback should do whatever is
        needed so that a GET on the 'url' returns the 'keyAuthorization',
        (which is what the Acme protocol calls the expected response.)

        [DNS] The callback may be called once for each domain name in the
        'issueCertificate' call. The callback should do whatever is
        needed so that a DNS query of the TXT record name in 'url'
        returns the value of 'keyAuthorization', (which is what the Acme
        protocol calls the expected response.)

        Note that this function may not be called in cases where
        Let's Encrypt already believes the caller has control
        of the domain name.
    */
    typedef void (*Callback) (  const std::string& domainName,
                                const std::string& url,                         // [HTTP] URL of the GET request; [DNS] record name of the TXT record
                                const std::string& keyAuthorization);           // [HTTP] Contents of the challenge file; [DNS] contents of the TXT record

    // Contact the Let's Encrypt production or staging environments
    enum class Environment { PRODUCTION, STAGING };

    // Specify the challenge type (HTTP or DNS). Note that wildcard certificates can only be issued by DNS challenges.
    enum class Challenge { HTTP, DNS };

    /**
        Issue a certificate for the domainNames.
        The first one will be the 'Subject' (CN) in the certificate.

        throws std::exception, usually an instance of acme_lw::AcmeException
    */
    Certificate issueCertificate(const std::list<std::string>& domainNames, Callback, Challenge chg = Challenge::HTTP);

    /**
        Call once before instantiating AcmeClient.
        
        Note that this calls Let's Encrypt servers and so can throw
        if they're having issues.
    */
    static void init(Environment env = Environment::PRODUCTION);

    // Call once before application shutdown.
    static void teardown();

private:
    std::unique_ptr<AcmeClientImpl> impl_;
};

}
