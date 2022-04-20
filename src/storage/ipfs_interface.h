#include <boost/algorithm/string.hpp>
#include <cpprest/filestream.h>
#include <cpprest/http_client.h>
#include <core_io.h>
#include <util/strencodings.h>
#include <primitives/block.h>

using namespace std;
using namespace utility;              // Common utilities like string conversions
using namespace web;                  // Common features like URIs.
using namespace web::http;            // Common HTTP functionality
using namespace web::http::client;    // HTTP client features
using namespace concurrency::streams; // Asynchronous streams
//////////////////////////////////////////////////////////////////////////////
// Author : Hank
// Date : 20190817
// Using Cpprest construct the block json

void CppRestProccessVoutToJson(CTxOut tx_Out, int counter, json::value& Vout);

void CppRestProccessScriptWitnessToJson(CScriptWitness scriptWitness, json::value& CScriptWitness);

void CppRestProccessVinToJson(CTxIn tx_in, int counter, json::value& Vin);

void CppRestProccessVtxToJson(vector<CTransactionRef> vtx, int vtx_size, json::value& root);

void CppRestConstructBlockToJson(CBlock block, json::value& root);

string AddToIPFS(string str);

void GetBlockFromIPFS(CBlock& block, string str);
std::string GetFromIPFS(std::string hash);

void PinIPFS(string str);

string readFileIntoString(const std::string& path);

std::vector<unsigned char> readFileToUnsignedChar(const std::string & path);

std::vector<unsigned char> StrHex(std::string str);