#include "acme-lw.h"

#include <cerrno>
#include <fstream>
#include <iostream>
#include <sstream>

#ifdef STD_FILESYSTEM
#include <filesystem>
namespace fs = std::filesystem;
#else
#include <experimental/filesystem>
namespace fs = std::experimental::filesystem;
#endif

using namespace std;

namespace
{

string readFile(const string& fileName);
void   writeFile(const string& fileName, const string& contents);

void handleHTTPChallenge(const string& domain, const string& url, const string& keyAuthorization)
{
    cout << "To verify ownership of " << domain << " make\n\n"
            << "\t" << url << "\n\nrespond with this:\n\n"
            << "\t" << keyAuthorization << "\n\n"
            << "Hit 'enter' when done";

    getchar();
    cout << "\n***\n";
}

void handleDNSChallenge(const string& domain, const string& dnsTXTname, const string& keyAuthorization)
{
    cout << "To verify ownership of " << domain << " create a DNS TXT record with name:\n\n"
            << "\t" << dnsTXTname << "\n\nand set it to the following value:\n\n"
            << "\t" << keyAuthorization << "\n\n"
            << "You'll need to wait for DNS propagation before the challenge can be verified.\n"
            << "This can take a few minutes, depending on your DNS provider.\n"
            << "You may want to check for DNS propagation to your host,\n"
            << "perhaps by running \"nslookup -q=TXT " << dnsTXTname << "\".\n\n"
            << "(Note that DNS propogation to your host does not necessarily mean that\n"
            << "propagation to the verifying servers has occurred.)\n\n"
            << "Hit 'enter' when done";

    getchar();
    cout << "\n***\n";
}

}

int main(int argc, char * argv[])
{
    if (argc < 3)
    {
        cout << "Usage is 'acme_lw_client [options] <file-name>, <domain-name>, <domain-name>, ...'\n"
                << "  * <file-name> holds the account private key in pem format\n"
                << "  * there must be at least one <domain-name>; the first will be the 'Subject' of the certificate\n"
                << "  * options are:\n"
                << "      -stg: use the Let's Encrypt staging environment (default is production)\n"
                << "      -dns: use a DNS challenge (default is HTTP)\n";
        return 0;
    }

    int exitStatus = 0;

    try
    {
        string accountPrivateKey = readFile(argv[1]);

        acme_lw::AcmeClient::Environment env = acme_lw::AcmeClient::Environment::PRODUCTION;
        acme_lw::AcmeClient::Challenge challenge = acme_lw::AcmeClient::Challenge::HTTP;

        list<string> domainNames;
        for (int i = 2; i < argc; ++i)
        {
            if ("-stg"s == argv[i])
            {
                env = acme_lw::AcmeClient::Environment::STAGING;
                continue;
            }
            if ("-dns"s == argv[i])
            {
                challenge = acme_lw::AcmeClient::Challenge::DNS;
                continue;
            }
            domainNames.push_back(argv[i]);
        }
        // Should be called once per process before a use of AcmeClient.
        acme_lw::AcmeClient::init(env);
        acme_lw::AcmeClient acmeClient(accountPrivateKey);

        acme_lw::AcmeClient::Callback callback = (challenge == acme_lw::AcmeClient::Challenge::HTTP) ? handleHTTPChallenge : 
                                                                                                       handleDNSChallenge;

        acme_lw::Certificate certificate = acmeClient.issueCertificate(domainNames, callback, challenge);

        writeFile("fullchain.pem", certificate.fullchain);
        writeFile("privkey.pem", certificate.privkey);

        cout << "Files 'fullchain.pem' and 'privkey.pem' have been written to the current directory.\n";
        cout << "Certificate expires on " << certificate.getExpiryDisplay() << "\n";
    }
    catch (const exception& e)
    {
        cout << "Failed with error: " << e.what() << "\n";
        exitStatus = 1;
    }

    // Should be called to free resources allocated in AcmeClient::init
    acme_lw::AcmeClient::teardown();

    return exitStatus;
}

namespace
{

string readFile(const string& fileName)
{
    ifstream f(fileName);
    if (f.fail())
    {
        cout << "Unable to open " << fileName << "\n";
        exit(1);
    }

    stringstream ss;
    ss << f.rdbuf();
    f.close();
    if (f.fail())
    {
        cout << "Failure reading " << fileName << "\n";
        exit(1);
    }

    return ss.str();
}

// Doesn't worry about permissions
void rawWriteFile(const string& fileName, const string& contents)
{
    ofstream f(fileName);
    if (f.fail())
    {
        cout << "Unable to write " << fileName << "\n";
        exit(1);
    }
    f.write(contents.c_str(), contents.size());
    f.close();
    if (f.fail())
    {
        cout << "Unable to write " << fileName << "\n";
        exit(1);
    }
}

// Write files with read / write permissions only to the current user.
void writeFile(const string& fileName, const string& contents)
{
    if (::remove(fileName.c_str()) && errno != ENOENT)
    {
        cout << errno << " Unable to remove " << fileName << "\n";
        exit(1);
    }

    rawWriteFile(fileName, "");
    fs::permissions(fileName, fs::perms::owner_read | fs::perms::owner_write);
    rawWriteFile(fileName, contents);
}

}
