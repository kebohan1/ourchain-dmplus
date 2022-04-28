#include <storage/ipfs_interface.h>

void CppRestProccessVoutToJson(CTxOut tx_Out, int counter, json::value& Vout)
{
    string test = HexStr(tx_Out.scriptPubKey);
    string formatTest = FormatScript(tx_Out.scriptPubKey);
    // CTxOut testOut = ToByteVector(test);
    CScript scriptPub = ParseScript(formatTest);
    Vout["CTxOut"][counter]["nValue"] = json::value::number(tx_Out.nValue);
    Vout["CTxOut"][counter]["ScriptPubkey"] = json::value::string(HexStr(tx_Out.scriptPubKey));
}

void CppRestProccessScriptWitnessToJson(CScriptWitness scriptWitness, json::value& CScriptWitness)
{
    // cout << "for loop of scriptwitness..." << endl;
    for (unsigned int i = 0; i < scriptWitness.stack.size(); i++) {
        // There's nothing show up, so I tried this to see what's going on.
        // cout << "CScriptWitness: " << HexStr(scriptWitness.stack[i]) << endl;
        CScriptWitness[i] = json::value::string(HexStr(scriptWitness.stack[i]));
    }
}

void CppRestProccessVinToJson(CTxIn tx_in, int counter, json::value& Vin)
{
    if (tx_in.prevout.IsNull())
        Vin["CTxIn"][counter]["coinbase"] = json::value::string(HexStr(tx_in.scriptSig));
    else
        Vin["CTxIn"][counter]["ScriptSig"] = json::value::string(HexStr(tx_in.scriptSig));
    if (tx_in.nSequence != tx_in.SEQUENCE_FINAL)
        Vin["CTxIn"][counter]["nSequence"] = json::value::number(tx_in.nSequence);

    // ProccessCOutPointToJson(Vin["CTxIn"]);
    Vin["CTxIn"][counter]["COutPoint"]["hash"] = json::value::string(tx_in.prevout.hash.ToString());
    Vin["CTxIn"][counter]["COutPoint"]["n"] = json::value::number(tx_in.prevout.n);
}

void CppRestProccessVtxToJson(vector<CTransactionRef> vtx, int vtx_size, json::value& root)
{
    int index = 0;
    root["vtx"]["size"] = json::value::number(vtx_size);

    for (const auto& it : vtx) {
        const CTransaction& tx = *it;
        string hexTx = EncodeHexTx(tx);
        // cout << "Uploaded hexTx:\n" << hexTx << endl;
        root["vtx"]["Txs"][index] = json::value::string(hexTx);
        index++;
        // cout << "Origin tx:\n" << tx.ToString() << endl;
        // CMutableTransaction Mtx;
        // DecodeHexTx(Mtx,hexTx,true);;

        // //CTransaction& decodedTx
        // CTransaction finaltx = CTransaction(Mtx);
        // cout << "Constructed finaltx: \n" << finaltx.ToString() << endl;
    }

    // for (CTransactionRef tx : vtx) {
    //     root["vtx"]["Txs"][index]["Txhash"] = json::value::string(tx->GetHash().ToString());
    //     root["vtx"]["Txs"][index]["nVersion"] = json::value::number(tx->nVersion);
    //     root["vtx"]["Txs"][index]["nLockTime"] = json::value::number(tx->nLockTime);

    //     root["vtx"]["Txs"][index]["Vin"]["size"] = json::value::number(tx->vin.size());
    //     root["vtx"]["Txs"][index]["Vout"]["size"] = json::value::number(tx->vout.size());

    //     //cout << "Proccessing Vin..." << endl;
    //     int tx_in_Counter = 0;
    //     for (CTxIn tx_in : tx->vin) {
    //         CppRestProccessVinToJson(tx_in, tx_in_Counter, root["vtx"]["Txs"][index]["Vin"]);
    //         tx_in_Counter++;
    //     }
    //     //cout << "Proccessing Vout..." << endl;
    //     int tx_out_Counter = 0;
    //     for (CTxOut tx_out : tx->vout) {
    //         CppRestProccessVoutToJson(tx_out, tx_out_Counter, root["vtx"]["Txs"][index]["Vout"]);
    //         tx_out_Counter++;
    //     }
    //     // cout << "Proccessing CScriptWitness..." << endl;
    //     for (CTxIn tx_in : tx->vin) {
    //         CppRestProccessScriptWitnessToJson(tx_in.scriptWitness, root["vtx"]["Txs"][index]["CscriptWitness"]);
    //     }
    //     index++;
    // }
}


void CppRestConstructBlockToJson(CBlock block, json::value& root)
{
    root["hash"] = json::value::string(block.GetHash().ToString());
    root["hashPrevBlock"] = json::value::string(block.hashPrevBlock.ToString());
    root["nVersion"] = json::value::number(block.nVersion);
    root["hashMerkleRoot"] = json::value::string(block.hashMerkleRoot.ToString());
    root["hashContractState"] = json::value::string(block.hashContractState.ToString());
    root["nTime"] = json::value::number(block.nTime);
    root["nBits"] = json::value::number(block.nBits);
    root["nNonce"] = json::value::number(block.nNonce);
    CppRestProccessVtxToJson(block.vtx, block.vtx.size(), root);

    // cout << "Construction completed...." << endl;
}


string AddToIPFS(string str)
{
    http_client client(U("http://127.0.0.1:5001/api/v0/add"));
    http_request request(methods::POST);

    string textBoundary = "--FORMBOUNDARY--";
    string textBody = "";
    textBody += "--" + textBoundary + "\r\n";
    textBody += "Content-Disposition:form-data;name=path\r\n";
    textBody += "\n" + str + "\r\n";
    textBody += "--" + textBoundary + "--\r\n";

    request.headers().set_content_type("multipart/form-data;boundary=--FORMBOUNDARY--");
    request.headers().set_content_length(textBody.length());
    request.set_body(textBody);
    // cout << postParameters << endl;
    pplx::task<http_response> responses = client.request(request);
    // cout << "responses.get() \n" << responses.get().to_string();

    pplx::task<string> s = responses.get().extract_string();

    json::value response = json::value::parse(s.get());
    std::string hashValue = response["Hash"].serialize();


    return hashValue.substr(1,hashValue.size()-2);
}

void GetBlockFromIPFS(CBlock& block, string str)
{
    // ---- change api from /object/get to /cat ---- Hank 20190902
    string request_uri = "/api/v0/cat?arg=" + str;
    http_client client(U("http://127.0.0.1:5001"));
    http_request request(methods::POST);
    // request.set_request_uri("/api/v0/object/get?arg=QmaaqrHyAQm7gALkRW8DcfGX3u8q9rWKnxEMmf7m9z515w&encoding=json");
    request.set_request_uri(request_uri);
    pplx::task<http_response> responses = client.request(request);
    pplx::task<string> responseStr = responses.get().extract_string();
    // LogPrintf("Response json:%s\n",responseStr.get());
    cout << "Response json:\n" << responseStr.get() << endl;

    //---- unserialize json string to the original CBlock data structure ---- Hank 20190902
    // CBlock block_json;    
    stringstream_t s;
    s << responseStr.get();
    json::value Response = json::value::parse(s);

    string temp = "";
    string blockHex = Response.serialize();
    // cout << "blockHex:\n" << blockHex << endl;

    block.nVersion = atoi(Response["nVersion"].serialize());
    // cout << "nVersion: " << atoi(Response["nVersion"].serialize()) << endl;
    
    temp = Response["hashMerkleRoot"].serialize();
    temp.erase(0,temp.find_first_not_of("\""));
    temp.erase(temp.find_last_not_of("\"")+1); 
    block.hashMerkleRoot = uint256S(temp);
    // cout << "hashMerkleRoot: " << Response["hashMerkleRoot"].serialize() << endl;

    temp = Response["hashPrevBlock"].serialize();
    temp.erase(0,temp.find_first_not_of("\""));
    temp.erase(temp.find_last_not_of("\"")+1); 
    block.hashPrevBlock = uint256S(temp);    
    // cout << "hashPrevBlock: " << Response["hashPrevBlock"].serialize() << endl;
    temp = Response["hashContractState"].serialize();
    temp.erase(0,temp.find_first_not_of("\""));
    temp.erase(temp.find_last_not_of("\"")+1); 
    block.hashContractState = uint256S(temp);    

    block.nTime = atoi(Response["nTime"].serialize());
    // cout << "nTime: " << Response["nTime"].serialize() << endl;
    block.nBits = atoi(Response["nBits"].serialize());
    // cout << "nBits: " << Response["nBits"].serialize() << endl;
    block.nNonce = atoi(Response["nNonce"].serialize());
    // cout << "nNonce: " << Response["nNonce"].serialize() << endl;
    
    for(int i =0; i < atoi(Response["vtx"]["size"].serialize()); i++){
        string txHex = Response["vtx"]["Txs"][i].serialize();
        txHex.erase(0,txHex.find_first_not_of("\""));
        txHex.erase(txHex.find_last_not_of("\"")+1);    
        // cout << "txHex: " << txHex << endl;   
        CMutableTransaction Mtx{};
        DecodeHexTx(Mtx,txHex,true);
        block.vtx.push_back(MakeTransactionRef(std::move(Mtx)));
    }      
    // CTransaction finaltx = CTransaction(Mtx);
    // cout << "finaltx:\n" << finaltx.ToString() << endl;
    // cout << block.ToString() << endl;
}

std::string GetFromIPFS(std::string hash){
  string request_uri = "/api/v0/cat?arg=" + hash;
  http_client client(U("http://127.0.0.1:5001"));
    http_request request(methods::POST);
    // request.set_request_uri("/api/v0/object/get?arg=QmaaqrHyAQm7gALkRW8DcfGX3u8q9rWKnxEMmf7m9z515w&encoding=json");
    request.set_request_uri(request_uri);
    pplx::task<http_response> responses = client.request(request);
    pplx::task<string> responseStr = responses.get().extract_string();
    // cout << "Response json:\n" << responseStr.get() << endl;
    return responseStr.get();
}

void PinIPFS(string str) {
  // ---- change api from /object/get to /cat ---- Hank 20190902
    string request_uri = "/api/v0/pin/add?arg=" + str +"&encoding=json";
    http_client client(U("http://127.0.0.1:5001"));
    http_request request(methods::POST);
    // request.set_request_uri("/api/v0/object/get?arg=QmaaqrHyAQm7gALkRW8DcfGX3u8q9rWKnxEMmf7m9z515w&encoding=json");
    request.set_request_uri(request_uri);
    pplx::task<http_response> responses = client.request(request);
    pplx::task<string> responseStr = responses.get().extract_string();
    // cout << "Response json:\n" << responseStr.get() << endl;
}

string readFileIntoString(const std::string& path) {
    struct stat sb{};
    std::string res;

    FILE* input_file = fopen(path.c_str(), "r");

    stat(path.c_str(), &sb);
    res.resize(sb.st_size);
    fread(const_cast<char*>(res.data()), sb.st_size, 1, input_file);
    fclose(input_file);

    return res;
}

std::vector<unsigned char> readFileToUnsignedChar(const std::string & path) {
    struct stat sb{};
    unsigned char* res;

    FILE* input_file = fopen(path.c_str(), "r");

    stat(path.c_str(), &sb);
    res = new unsigned char[sb.st_size];
    
    fread(res, sb.st_size,1 ,input_file);
    return std::vector<unsigned char>(res, res +  sb.st_size);;
}

unsigned int charVal(char i){
    return (i >= '0' && i <= '9') ? i - '0' : i - 'a' + 10;
}

std::vector<unsigned char> StrHex(std::string str)
{
    std::vector<unsigned char> rv;
    const char* cStr = str.c_str();
    static const char hexmap[16] = { '0', '1', '2', '3', '4', '5', '6', '7',
                                     '8', '9', 'a', 'b', 'c', 'd', 'e', 'f' };
    for(int i = 0; i< str.length(); i += 2) {
        unsigned char val = charVal(cStr[i]);
        val <<=4;
        val += charVal(cStr[i + 1]);
        rv.push_back(val);
    }

    return rv;
}