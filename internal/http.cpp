#include "http.h"

#include "acme-exception.h"

#include "json.hpp"

#include <curl/curl.h>

#include <cstring>
#include <mutex>
#include <stack>

using namespace std;

using namespace acme_lw;

namespace
{

struct Ptr
{
    Ptr()
        : curl_(curl_easy_init())
    {
        if (!curl_)
        {
            throw acme_lw::AcmeException("Error initializing curl");
        }
    }

    ~Ptr()
    {
        curl_easy_cleanup(curl_);
    }

    CURL * operator * () const
    {
        return curl_;
    }

private:
    CURL * curl_;
};

void getNonce_();

// https://datatracker.ietf.org/doc/html/rfc8555#section-6.5
struct NonceCollection
{
    stack<string> nonces_;
    time_t        timeout_;
    mutex         mutex_;
    short         failCount_;

    NonceCollection()
        : timeout_(0), failCount_(0)
    {
    }

    string getNonce()
    {
        string nonce;
        {
            unique_lock<mutex> lock(mutex_);
            failCount_++;
            if (!nonces_.empty())
            {
                // Only keep nonces around for 10 minutes. They
                // expire sometime and it's not super expensive 
                // to get another one.
                if (::time(nullptr) - timeout_ > 60 * 10)
                {
                    nonces_ = stack<string>();
                }
                else
                {
                    nonce = nonces_.top();
                    nonces_.pop();
                    failCount_ = 0;
                }
            }

            if (failCount_ > 10)
            {
                // For some reason we aren't getting nonces.
                throw AcmeException("Unable to get a nonce");
            }
        }

        if (!nonce.empty())
        {
            return nonce;
        }

        getNonce_();

        return this->getNonce();
    }

    void addNonce(string&& nonce)
    {
        unique_lock<mutex> lock(mutex_);
        nonces_.push(move(nonce));
        timeout_ = ::time(nullptr);
    }
};

NonceCollection nonceCollection;

string getHeaderValue(const char * key, const char * data, size_t byteCount)
{
    size_t keyLen = strlen(key);
    if (byteCount >= keyLen)
    {
        // Header names are case insensitive per RFC 7230. Let's Encrypt's move
        // to a CDN made the headers lower case.
        if (!strncasecmp(key, data, keyLen))
        {
            string line(data, byteCount);

            // Header looks like 'X: Y'. This gets the 'Y'
            auto pos = line.find(": ");
            if (pos != string::npos)
            {
                string value = line.substr(pos + 2, byteCount - pos - 2);

                // Trim trailing whitespace
                return value.erase(value.find_last_not_of(" \n\r") + 1);
            }
        }
    }
    return "";
}

size_t headerCallback(void * buffer, size_t size, size_t nmemb, void * h)
{
    size_t byteCount = size * nmemb;
    if (h)
    {
        // header -> 'key': 'value'
        pair<string, string>& header = *reinterpret_cast<pair<string, string> *>(h);

        string value = getHeaderValue(header.first.c_str(), reinterpret_cast<const char *>(buffer), byteCount);
        if (value.size())
        {
            header.second = value;
        }
    }

    string nonce = getHeaderValue("replay-nonce", reinterpret_cast<const char *>(buffer), byteCount);
    if (nonce.size())
    {
        nonceCollection.addNonce(move(nonce));
    }

    return byteCount;
}

size_t dataCallback(void * buffer, size_t size, size_t nmemb, void * response)
{
    vector<char>& v = *reinterpret_cast<vector<char> *>(response);

    size_t byteCount = size * nmemb;

    size_t initSize = v.size();
    v.resize(initSize + byteCount);
    memcpy(&v[initSize], buffer, byteCount);

    return byteCount;
}

string getCurlError(const string& s, CURLcode c)
{
    return s + ": " + curl_easy_strerror(c);
}

enum class Result { SUCCESS, BAD_NONCE };

Result doCurl(Ptr& curl, const string& url, const vector<char>& response)
{
    auto res = curl_easy_perform(*curl);
    if (res != CURLE_OK)
    {
        throw AcmeException(getCurlError("Failure contacting "s + url +" to read a header.", res));
    }

    long responseCode;
    curl_easy_getinfo(*curl, CURLINFO_RESPONSE_CODE, &responseCode);
    if (responseCode / 100 != 2)
    {
        if (responseCode == 400)
        {
            auto json = nlohmann::json::parse(response);
            if (json.at("type") == "urn:ietf:params:acme:error:badNonce")
            {
                return Result::BAD_NONCE;
            }
        }
        // If it's not a 2xx response code, throw.
        throw AcmeException("Response code of "s + to_string(responseCode) + " contacting " + url + 
                            " with response of:\n" + string(&response.front(), response.size()));
    }

    return Result::SUCCESS;
}

string newNonceUrl;

void getNonce_()
{
    Ptr curl;
    curl_easy_setopt(*curl, CURLOPT_URL, newNonceUrl.c_str());

    // Does a HEAD request
    curl_easy_setopt(*curl, CURLOPT_NOBODY, 1);

    curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, &headerCallback);

    // There will be no response (probably). We just pass this
    // for error handling
    vector<char> response;
    doCurl(curl, newNonceUrl, response);
}

}

namespace acme_lw_internal
{

void initHttp()
{
    curl_global_init(CURL_GLOBAL_DEFAULT);
}

void teardownHttp()
{
    curl_global_cleanup();
}

void initNonce(const string& nnu)
{
    newNonceUrl = nnu;
}

string getNonce()
{
    return nonceCollection.getNonce();
}

Response doPost(const string& url, const string& postBody, const char * headerKey)
{
    Response response;

    Ptr curl;

    curl_easy_setopt(*curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(*curl, CURLOPT_POST, 1);
    curl_easy_setopt(*curl, CURLOPT_POSTFIELDS, postBody.c_str());
    curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, dataCallback);
    curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &response.response_);

    curl_slist h = { const_cast<char *>("Content-Type: application/jose+json"), nullptr };
    curl_easy_setopt(*curl, CURLOPT_HTTPHEADER, &h);

    pair<string, string> header;
    curl_easy_setopt(*curl, CURLOPT_HEADERFUNCTION, &headerCallback);
    if (headerKey)
    {
        header = make_pair(headerKey, ""s);
        curl_easy_setopt(*curl, CURLOPT_HEADERDATA, &header);
    }
    else
    {
        curl_easy_setopt(*curl, CURLOPT_HEADERDATA, nullptr);
    }
    
    response.badNonce_ = doCurl(curl, url, response.response_) == Result::BAD_NONCE;

    response.headerValue_ = header.second;

    return response;
}

vector<char> doGet(const string& url)
{
    vector<char> response;

    Ptr curl;

    curl_easy_setopt(*curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(*curl, CURLOPT_WRITEFUNCTION, dataCallback);
    curl_easy_setopt(*curl, CURLOPT_WRITEDATA, &response);

    doCurl(curl, url, response);

    return response;
}

}

