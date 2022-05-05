#pragma once

#include <string>
#include <vector>

namespace acme_lw_internal
{

std::vector<char> doGet(const std::string& url);

struct Response
{
    std::vector<char>   response_;
    std::string         headerValue_;
    bool                badNonce_;    
};

Response doPost(const std::string& url, const std::string& postBody, const char * headerKey = nullptr);

std::string getNonce();

void initHttp();
void initNonce(const std::string& newNonceUrl);
void teardownHttp();

}
