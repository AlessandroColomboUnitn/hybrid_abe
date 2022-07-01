#include "habe_sk.h"

const string NULL_SK = "nill";
const string PWD = "test";
OpenABEByteString iv, tag;
string MPK;

map<string, pair<string, string>> T;
map<string, string> UA;
map<string, pair<string, string>> U;



//----------------------------------------------Client implementation--------------------------------------

/*
*   Setup the client
*   @param uid id to associate with the client
*/
Client::Client(const string &uid) : cpabe("CP-ABE"){
    //cpabe.enableKeyManager(uid);
    cpabe.importPublicParams(MPK); //import Master Public Key initialised by Attribute Authority
    this->uid = uid;
}

/*
*   Decrypt and store the client's secret key
*  
*/
bool Client::get_sk(){

    cout << uid <<": retrieving SK...\n";
    
    auto item = U.find(uid);
    if (item != U.end()){
        string ct = item->second.second; //retrieve ciphertext of client's SK from U table
        string sk; 
        pke.decrypt(uid, ct, sk); //decrypt SK with client's K_dec
        cpabe.deleteKey(uid); //in case of update we need to delete previous sk
        cpabe.importUserKey(uid, sk); //import client's SK in client's context
        return true;
    }
    return false;
}

/*
*   Generate the client's asymmetric key pair. Insert the public key in the metadata storage.
*/
void Client::generate_pke(){
    cout << uid <<": generating asymmetric key pair...\n";
    string k_enc;
    pke.keygen(uid); //generate client's asymmetric key pair (K_enc, K_dec) and store under uid
    pke.exportPublicKey(uid, k_enc);  
    U[uid] = {k_enc, NULL_SK}; //publish k_enc in U table
}

//retrieve, decrypt and store topic "t" symmetric key, notify error if user non authorized or "t" doesn't exists 
/*
*   Decrypt and store the symmetric key associated with a certain topic.
*   @param t name of the specific topic
*   @return OpenABE_NOERROR if no error occured, the error code otherwise
*/
OpenABE_ERROR Client::get_topic_key(const string& t){
    auto item = T.find(t);
    OpenABE_ERROR result = OpenABE_NOERROR;
    try{
        ASSERT(item!=T.end(), OpenABE_ERROR_ELEMENT_NOT_FOUND);
        string ct, pt;
        ct = item->second.first;
        ASSERT(cpabe.decrypt(uid, ct, pt), OpenABE_ERROR_INVALID_KEY);
        OpenABEByteString skey;
        skey.fromString(pt);
        sym.loadPrivateKey(t, skey, PWD);
    }catch(OpenABE_ERROR error){
        result = error;
    }
    return result;
}

/*
* Initialize the publisher
*/
Publisher::Publisher(string& uid) : Client(uid){
}


//TODO: version topics to avoid getting and decrypting symmetric key at each call
/*
*   Encrypt a message under the symmetric key associated with a certain topic
*   @param[in] t topic name
*   @param[in] pt message to encrypt
*   @param[out] ct encrypted message
*/
bool Publisher::publish(const string& t, const string& pt, string& ct){

    if( /*sym.encryptInit(t, &iv)==OpenABE_NOERROR ||*/ (get_topic_key(t)==OpenABE_NOERROR && sym.encryptInit(t, &iv)==OpenABE_NOERROR) ){ //remove comment when integrated with broker's "updated topic" messages, to avoid retrieving symmetric key each time 
        cout << uid << ": encripting message ...\n";
        OpenABEByteString _pt, _ct;
        _pt.fromString(pt);
        sym.encryptUpdate(&_pt, &_ct);
        sym.encryptFinalize(&_ct, &tag);
        ct = _ct.toString();
        return true;
    }

    return false;
}

//----------------------------------------------Subscriber implementation--------------------------------------

/*
* Initialize subscriber
*/
Subscriber::Subscriber(string& uid): Client(uid){
}


/*
* Decrypt a message published under a certain topic.
* @todo remove comment in the first "if" when integrated with broker's "update topic" messages, to avoid retrieving symmetric key each time
* @param[in] t name of the topic
* @param[in] ct encrypted message
* @param[out] pt original message
*/
bool Subscriber::subscribe(const string &t, const string& ct, string& pt){
        cout << uid << ": decrypting...\n";
        if (/*sym.decryptInit(t, &iv, &tag)==OpenABE_NOERROR ||*/ (get_topic_key(t)==OpenABE_NOERROR && sym.decryptInit(t, &iv, &tag)==OpenABE_NOERROR) ){ //remove comment when integrated with broker's "update topic" messages, to avoid retrieving symmetric key each time
            OpenABE_ERROR result = OpenABE_NOERROR;
            OpenABEByteString _pt, _ct;
            _ct.fromString(ct);
            try{
                result = sym.decryptUpdate(&_ct, &_pt);
                ASSERT (result==OpenABE_NOERROR, OpenABE_ERROR_DECRYPTION_FAILED);
                result = sym.decryptFinalize(&_pt);
                ASSERT (result==OpenABE_NOERROR, OpenABE_ERROR_DECRYPTION_FAILED);
                pt = _pt.toString();
                return true;
            }catch(OpenABE_ERROR result){
                cout<<"Decryption failed\n";
            }
        }        
        return false;
}

//----------------------------------------------AA implementation--------------------------------------

/*
* Initialize Attibute Authority.
*/
AA::AA():cpabe("CP-ABE"){
    setup();
}


/*
* Add a user in the system (user enrollment).
* 
* @param uid id of the user to add  
* @param l attribute list associated with the new user
*/
bool AA::addU(const string &uid, const string &l){
    UA[uid] = l;
    add_attributes(l);
    auto item = U.find(uid);
    if (item != U.end()){
        if (item->second.second == NULL_SK){
            keyGen(uid);
            return true;
        }
        else{
            cerr << "cannot initialize already existent user\n";
            return false;
        }
    }
    cerr << "user must be initialized before assignment\n";
    return false;
}

/*
* Delete a user from the system (user revocation).
* 
* @param uid id of the user to revoke  
*/
void AA::delU(const string& uid){
    auto item = UA.find(uid);
    try{
        ASSERT(item!=UA.end(), OpenABE_ERROR_ELEMENT_NOT_FOUND);
        string l = item->second;
        revokeA(uid,l);
    }catch(OpenABE_ERROR err){
        cerr<<"Cannot delete non existing user\n";
    }
}


/*
* Create a new topic protected by the access structure as.
* 
* @param t name of the specific topic  
* @param as name of the protecting access structure  
*/
void AA::addT(const string& t, const string& as){
    OpenABEByteString skey;
    string ct;
    sym.keygen(t);
    sym.exportKey(t, skey, PWD);
    cpabe.encrypt(as,skey.toString(),ct);
    //cout<<skey<<endl;
    T[t] = {ct, as};
}


/*
* Change the access structure protecting a certain topic.
* 
* @param t name of the specific topic  
* @param as name of the new access structure  
*/
void AA::updateT(const string& t, const string& as){
    auto elem = T.find(t);
    try{
        ASSERT(elem != T.end(), OpenABE_ERROR_ELEMENT_NOT_FOUND);
        string old_as = elem->second.second;
        if(old_as != as){
            //implement no update if all previously authorized user are still authorized  
            addT(t, as);
        }
    }catch(OpenABE_ERROR err){

    }
}


/*
* Delete a certain topic from the system.
* 
* @param t name of the topic to remove 
* 
*/
void AA::delT(const string& t){
    try{
        ASSERT(T.erase(t), OpenABE_ERROR_ELEMENT_NOT_FOUND);
    }catch(OpenABE_ERROR err){

    }
}

/*
* Add a list of attributes to the one associated with a certain user.
* 
* @param uid id of the specific user
* @param l list of attributes to add 
* 
*/
void AA::addA(const string& uid, const string& l){
    try{
        auto elem = UA.find(uid);
        ASSERT(elem != UA.end(), OpenABE_ERROR_ELEMENT_NOT_FOUND);
        elem->second = l;
    }catch(OpenABE_ERROR err){

    }
}


/*
* Revoke a list of attributes to a certain user.
* 
* @param uid id of the specific user
* @param l list of attributes to revoke 
* 
*/
void AA::revokeA(const string& uid, const string& l){
    string delim="|";
    string al = l+delim;
    auto elem = UA.find(uid);
    if(elem != UA.end()){
        string ul = elem->second;
        string attribute;
        vector<string> to_revoke;
        size_t pos;

        while((pos = al.find(delim)) != string::npos){
            attribute = al.substr(0,pos);
            al.erase(0, pos+delim.size());
            if(attribute.empty()) continue;
            const size_t pos_u = ul.find(delim+attribute);
            if(pos_u != string::npos){ //only if the attribute is actually contained in uid's al we need to perform the updates
                ul.erase(pos_u, delim.length()+attribute.length()); //remove old attribute from uid's al
                to_revoke.push_back(attribute);
            }
        }
        UA[uid]=ul;
        vector<string> new_versions(to_revoke.size());
        attNewVersions(to_revoke, new_versions);
        reversion_lists(to_revoke, new_versions); //update all attribute lists containing "attribute"
        reversion_topics(to_revoke, new_versions); //update all symmetric key protected by access structure containing "attribute"
    }
}

/*
* Delete a list of attributes from the system
* @param l list of attributes to erase
*/
void AA::delA(const string& l){
    string delim="|";
    string al = l+delim;
    vector<string> to_erase;
    size_t pos;
    while((pos = al.find(delim)) != string::npos){
        string attribute = al.substr(0,pos);
        al.erase(0, pos+delim.length());
        if(attribute.empty()) continue;
        to_erase.push_back(attribute);
    }

    for(auto& item : T){
        string t = item.first;
        string as = item.second.second;
        bool refresh = false;
        
        for(string attribute : to_erase){
            regex r ("( or "+attribute+")+|("+attribute+" or )+|( and "+attribute+")+|("+attribute+" and )+|("+attribute+")+");
            string new_as = regex_replace(as, r, "");
            if(as != new_as) {
                refresh=true;
                as = new_as;
            }
        }

        if(refresh) {
            if(as.empty()) delT(t);
            else addT(t,as);
        }
    }

    for(auto& item : UA){
        string uid = item.first;
        string l = item.second;
        bool refresh = false;
        
        for(string attribute: to_erase){
            string new_l = regex_replace(l, regex("\\|"+attribute), "");
            if(new_l != l) {
                refresh = true;
                l = new_l;
            }
        }

        if(refresh){
            item.second = l;
            cout<<uid<<" "<<l<<endl;
            if(!l.empty()) keyGen(uid);
        }
    }
}


/*
*   Generate the ABE secret key associated with a specific user. 
*   @param uid id of the specific user
*/
OpenABE_ERROR AA::keyGen(const string& uid){

    //cout<<al<<endl;
    auto item1 = U.find(uid); //U elements are (uid, (pk, sk))
    auto item2 = UA.find(uid); //UA elements are (uid, l)
    OpenABE_ERROR result = OpenABE_NOERROR;

    try{
        ASSERT((item1 != U.end()) && (item2 != UA.end()), OpenABE_ERROR_ELEMENT_NOT_FOUND); //"uid" is actually a valid user id and is associated with an attribute list
        string sk, ct; //"sk" will contain ABE secret key, ct will be encryption of "sk" under "al"
        string al = item2->second;
        cpabe.keygen(al, uid);
        cpabe.exportUserKey(uid, sk);
        string pk = item1->second.first; //gey public key
        pke.importPublicKey(uid, pk);
        ASSERT(pke.encrypt(uid, sk, ct), OpenABE_ERROR_ENCRYPTION_ERROR); //encryption is successfull
        item1->second.second = ct; //insert secret key
        cpabe.deleteKey(uid); //don't need to maintain secret key in AA local context
    }catch(OpenABE_ERROR error){
        result = error;
    }
    return result;
}


/*
* Print the status of UA and T tables (debugging).
*/
void AA::print_status(){
    for(auto x : UA) cout<<x.first<<" attribute list:\n"<<x.second<<endl;
    for(auto x : T) cout<<x.first<<" access structure:\n"<<x.second.second<<endl;
}


/*
* Setup the AA.
*/
void AA::setup(){
    cout << "AA: initializing PK & MSK ...\n";
    cpabe.generateParams();
    cpabe.exportPublicParams(MPK); // make master public key available for all
}


/*
* Keep track of a list of new attributes in the map "attribute version"  
*/
void AA::add_attributes(const string& al){
    string attribute;
    stringstream test(al);
    while(getline(test, attribute, '|')){
        attributes_version.insert({attribute, 0});
    }
}


/*
*   Outputs an attrtibute list containing the updated version of all attributes in the input list 
*   @param[in] old_atts input attribute list
*   @param[out] new_atts output attribute list containing updated versions 
*/
void AA::attNewVersions(const vector<string>& old_atts, vector<string>& new_atts){
    for(size_t i = 0; i<old_atts.size(); i++){ //save new version of attributes to revoke into new_atts
        string att = old_atts[i];
        size_t pos;
        if( (pos = att.find("_")) != string::npos){
            att = att.substr(0, pos);
        }
        int ver = ++attributes_version[att];
        new_atts[i] = att+"_"+to_string(ver);
    }
}



/*
*   Update all attribute lists containing old attributes with new attributes. If at least one update occurred, regenerate the user's ABE secret key.
*   @param old_atts attribute list containing old versions
*   @param new_atts attribute list containing updated versions
*/
void AA::reversion_lists(const vector<string>& old_atts, const vector<string>& new_atts){

    for(auto& elem : UA){ //iterate over all pairs (u, l)
        string uid = elem.first; //get user's id
        string l = elem.second; //get user's attribute attribute list
        bool refresh = false;
        for(size_t i = 0; i<old_atts.size(); i++){
            string old_att = old_atts[i], new_att = new_atts[i];
            string new_l = regex_replace(l, regex(old_att), new_att);
            if(new_l != l){
                l = new_l;
                refresh = true;
            }
        } 
        
        if(refresh){ //if we updated u's attribute list we have to re-generate his sk
            elem.second = l;
            keyGen(uid);
        }
    }   
}


/*
*   Update all topics' access structures containing some old attributes with new attributes. If needed, regenerate the topic's symmetric key.
*   @todo don't regenerate topic's key if not needed (all previously authorized users are still authorized)
*   @param old_atts attribute list containing old versions
*   @param new_atts attribute list containing updated versions
*/
void AA::reversion_topics(const vector<string>& old_atts, const vector<string>& new_atts){
    for(auto & elem : T){
        string t = elem.first; //get topic name
        string as = elem.second.second; //get protecting access structure  
        bool refresh_key = false;

        for(size_t i = 0; i<old_atts.size(); i++){
            string old_att = old_atts[i], new_att = new_atts[i];
            string new_as = regex_replace(as, regex(old_att), new_att); //if old_att in as, replace attribute version and save result in "new_as"
            if(new_as != as) { //if new_as is different from as, we (might) have to update symmetric key 
                as = new_as;
                refresh_key=true;
            }
        }

        if(refresh_key){
            sym.deleteKey(t);
            addT(t, as);
        }

    }
}
