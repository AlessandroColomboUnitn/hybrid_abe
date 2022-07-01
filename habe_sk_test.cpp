#include "habe_sk.h"

string pub_uid="thermometer", sub_uid="heatingSystem", unauth_uid = "smartTV";
string l1="|thermometer|floor1|smartsensor", l2="|heatingSystem|floor1|smarthome", l3 = "|smartTV|floor2|smarthome"; 
string t="floor1/temperature", as="((thermometer or smarthome) and floor1)"; 

int main(){
    InitializeOpenABE();
    
    AA kga;
    Publisher pub (pub_uid); Subscriber sub (sub_uid);
    
    cout<<"\n--------------------------------\n";
    cout<<"Classic example with authorized "<<pub_uid<<" and "<<sub_uid<<"\n\n";
    kga.addT(t, as);
    pub.generate_pke(); sub.generate_pke();
    kga.addU(pub_uid, l1); kga.addU(sub_uid,l2);
    pub.get_sk(); sub.get_sk();
    string pt = "temperature:24,\nstatus ok", ct;
    pub.publish(t, pt, ct);
    cout<<"published message:\n"<<ct<<endl;
    string pt2;
    sub.subscribe(t, ct, pt2);
    cout<<"retrieved message:\n"<<pt2<<"\n";

    cout<<"\n----------------------------------\n";
    cout<<"Example with unauthorized smartTV\n";
    Subscriber unauth(unauth_uid);
    string pt3;
    unauth.generate_pke();
    kga.addU(unauth_uid, l3);
    unauth.get_sk();
    unauth.subscribe(t,ct,pt3);
    
    cout<<"\n----------------------------------\n";
    cout<<"Revocation of attribute floor1 to "<<sub_uid<<endl<<endl;
    
    kga.revokeA(sub_uid, "|floor1|smarthome|random");
    kga.print_status();
    cout<<endl;

    pt="temperature:26\nstatus:ok", pt2="";
    
    pub.get_sk(); 
    pub.publish(t, pt, ct);
    sub.subscribe(t, ct, pt2); 
    
    cout<<sub_uid<<", message received: \n"<<pt2<<endl;

    cout<<"\n-----------------------------------\n";
    string t2 = "energy_cosumption", as2 = "(smartTV or heatingSystem)";
    cout<<"Creating new topic: "<<t2<<", protected by: "<<as2;
    kga.addT(t2, as2);
    cout<<"Delete attribute heatingSystem\n";
    kga.delA("|heatingSystem");
    kga.print_status();

    cout<<"\n-----------------------------------\n";
    string as3 = "(smartTV and floor1)";
    cout<<"Updating as of topic "<<t2<<endl;
    kga.updateT(t2, as3);
    kga.print_status();

    cout<<"\n-----------------------------------\n";
    cout<<"Deleting topic "<<t2<<endl;
    kga.delT(t2);
    kga.print_status();

    cout<<"\n-----------------------------------\n";
    string al = "|floor3|smartHome_1";
    cout<<"Adding attributes "<<al<<" to "<<sub_uid<<endl;
    kga.addA(sub_uid, al);
    kga.print_status();

    ShutdownOpenABE();
    return 0;
}