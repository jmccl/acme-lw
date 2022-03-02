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

void handleChallenge(const string& domain, const string& url, const string& keyAuthorization)
{
    cout << "To verify ownership of " << domain << " make\n\n"
            << "\t" << url << "\n\nrespond with this\n\n"
            << "\t" << keyAuthorization << "\n\n"
            << "Hit any key when done";

    getchar();
    cout << "\n***\n";
}

}

int main(int argc, char * argv[])
{
#ifdef STAGING
    cout << "Running against staging environment.\n\n";
#endif

    if (argc < 3)
    {
        cout << "Usage is 'acme_lw_client <file-name>, <domain-name>, <domain-name>, ...'\n"
                << "  * <file-name> holds the account private key in pem format\n"
                << "  * there must be at least one <domain-name>; the first will be the 'Subject' of the certificate\n";
        return 0;
    }

    int exitStatus = 0;

    try
    {
        // Should be called once per process before a use of AcmeClient.
        acme_lw::AcmeClient::init();

        string accountPrivateKey = readFile(argv[1]);
        acme_lw::AcmeClient acmeClient(accountPrivateKey);

        list<string> domainNames;
        for (int i = 2; i < argc; ++i)
        {
            domainNames.push_back(argv[i]);
        }

        acme_lw::Certificate certificate = acmeClient.issueCertificate(domainNames, handleChallenge);

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
