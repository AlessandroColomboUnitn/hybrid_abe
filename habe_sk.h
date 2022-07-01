#ifndef __HABE_H__
#define __HABE_H__

#include <iostream>
#include <string>
#include <cassert>
#include <map>
#include <unordered_map>
#include <vector>
#include <regex>
#include <openabe/zsymcrypto.h>
#include <openabe/openabe.h>

using namespace std;
using namespace oabe;
using namespace oabe::crypto;


class Client{
protected:
    OpenPKEContext pke; //for generating and storing client generating asymmetric key pair + PKE algorithms
    OpenABECryptoContext cpabe; //for generating and storing ABE keys + ABE algorithms
    OpenABEContextSchemeStreamSKE sym; //for generating and storing symm keys + AES enc/dec
    string uid;
    OpenABE_ERROR get_topic_key(const string& t);
public:
    Client(const string &uid);
    void generate_pke(); //Generate asymmetric key pair (K_enc, K_dec) and publish K_enc
    bool get_sk(); //Use K_dec to retreive SK
};

class Publisher : public Client{
public:
    Publisher(string& uid); 
    bool publish(const string& t, const string& pt, string& ct); //Encrypt "pt" under access structure protecting "t" and put result in "ct"
};

class Subscriber : public Client{
public:
    Subscriber(string& uid);
    bool subscribe(const string &t, const string& ct, string& pt); //Decrypt message "ct" of topic "t" and put result in "pt"
};

class AA{
    OpenPKEContext pke;
    OpenABECryptoContext cpabe;
    OpenABEContextSchemeStreamSKE sym;
    unordered_map<string, int> attributes_version;
public:
    AA();
    bool addU(const string& uid, const string& l); //associates user "uid" with attributes in attribute list "l"
    void delU(const string& u);
    void addT(const string& t, const string& as);
    void updateT(const string& t, const string& as);
    void delT(const string& t);
    void addA(const string& uid, const string& l);
    void revokeA(const string& uid, const string& l);
    void delA(const string& l);
    void print_status(); //debugging
    OpenABE_ERROR keyGen(const string& uid);
private:
    void setup();
    void add_attributes(const string& al);
    void attNewVersions(const vector<string>& old_atts, vector<string>& new_atts);
    void reversion_lists(const vector<string>& old_atts, const vector<string>& new_atts);
    void reversion_topics(const vector<string>& old_atts, const vector<string>& new_atts);
};




#endif