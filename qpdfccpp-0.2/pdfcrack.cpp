/**
 * Copyright (C) 2013 Matteo Tamigi
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
*/

#include "pdfcrack.hpp"
#include <iostream>
using namespace std;

/** sets the number of bytes to decrypt for partial test.
    Three should be a good number for this as this mean a match should only
    happen every 256^3=16777216 check and that should be unique enough to
    motivate a full retry on that entry.
 */
#define PARTIAL_TEST_SIZE 3



//METODI RIGUARDANTI LA CLASSE PADRE PDFCrack
//----------------------------------------------------------------------------//
PDFCrack :: PDFCrack () {
    //Azzero tutti i puntatori
	charSet = nullptr;
    state = new int[32];
	o_key = nullptr;
	u_key = nullptr;
	o_string = nullptr;
	u_string = nullptr;
	opad = nullptr;
    //Imposto le variabili a 0
    lenSet = 0;
    numCifr = 0;
    lenState = 0;
    u_found = false;
    o_found = false;
    eos = false;
    length = 0;
    user_pswd = true;       //true: c'è oppure non lo so | false: non c'è
    //Genero i vettori di supporto
    digest = new uint8_t[16];
    tmp = new uint8_t[32];
    key2 = new uint8_t[128];
    tmpkey = new uint8_t[16];
}

PDFCrack :: ~PDFCrack () {
    if(charSet)
        delete [] charSet;
    if(state)
        delete [] state;
    if( u_key )
        delete [] u_key;
    if( o_key )
        delete [] o_key;
    if( o_string )
        delete [] o_string;
    if( u_string )
        delete [] u_string;
    if( opad )
        delete [] opad;
    if( tmp )
        delete [] tmp;
    if( key2 )
        delete [] key2;
    if(tmpkey)
        delete [] tmpkey;
}

void PDFCrack :: SetWs ( EncWorkSpace w ) {
    //AnzichÃ© copiare la variabile, istanzio direttamente tutte le variabili di
    //lavoro (guadagno un inizializzazione veloce anzichÃ¨ una copia)
    //Azzero tutti i puntatori e li cancello
    if( u_key )
        delete [] u_key;
    if( o_key )
        delete [] o_key;
    if( o_string )
        delete [] o_string;
    if( u_string )
        delete [] u_string;
    if( opad )
        delete [] opad;
    //Alloco e carico le informazioni
    u_key = new uint8_t[w.u_key.size()];
    o_key = new uint8_t[w.o_key.size()];
    o_string = new uint8_t[w.o_string.size()];
    u_string = new uint8_t[w.u_string.size()];
    opad = new uint8_t[w.own_pad.size()];
    for(unsigned i = 0; i < w.u_key.size(); i++) {
        u_key[i] = w.u_key[i];
        o_key[i] = w.o_key[i];
    }
    for(unsigned i = 0; i < w.o_string.size(); i++)
        o_string[i] = w.o_string[i];
    for(unsigned i = 0; i < w.u_string.size(); i++)
        u_string[i] = w.u_string[i];
    for(unsigned i = 0; i < w.own_pad.size(); i++)
        opad[i] = w.own_pad[i];
    length = w.length/8;
    sizeKey = w.u_key.size();
    user_pswd = w.user_pswd;
}

void PDFCrack :: SetCiphers ( int num ) {
    numCifr = num;
}

void PDFCrack :: SetCharset ( const string chs ) {
    if(charSet)
        delete [] charSet;
    lenSet = chs.length();
    charSet = new uint8_t[lenSet];
    for(unsigned i = 0; i < lenSet; i++)
        charSet[i] = (uint8_t)chs[i];
}


//Accetto SEMPRE e SOLO vettori st lunghi almeno 32!!!
//inoltre si presume che lo stato sia sempre >= delle cifre da ciclare
void PDFCrack :: SetState ( int len , int * st = nullptr ) {
    //Genero il vettore degli stati e lo carico (o lo azzero)
    if( st ) {
        //Copio lo stato
        for(int i = 0; i < 32; i++)
            state[i] = st[i];
        //lenState = len;
        unsigned i = 0;
        while(i < 32) {
            if( state[i] == -1) {
                lenState = i;
                break;
            }
            i++;
        }
    } else {
        for(unsigned i = 0; i < len; i++)
            state[i] = 0;
        for(unsigned i = len; i < 32; i++)
            state[i] = -1;
        lenState = len;
    }
    eos = false;
    o_found = false;
    u_found = false;
    //DEBUG
    /*cout << "PC: range=" << numCifr << " stato=";
    for(int i = 0; i < 32; i++)
        cout << st[i] << ",";
    cout << endl;*/
}

string PDFCrack :: GetCurrentPassword () {
    string str;
    for(unsigned i = 0; i < lenState; i++)
        str.push_back( charSet[state[i]] );
    return str;
}

//Questa funzione lavora direttamente sul vettore key (per risparimiare lavoro)
void PDFCrack :: SetNextPassword () {
    if( !eos ) {
        //Incremento la combinazione di 1
        register unsigned i = 0;
        while ( i < numCifr ) {
            if( ++state[i] < lenSet ) {
                key[i] = charSet[state[i++]];
                break;
            }
            else {
                //Sono all'ultima combinazione con 'i' cifre, genero la successiva
                state[i] = 0;
                key[i++] = charSet[0];
                //Ciclo di password finito
                if( i == numCifr ) {
                    eos = true;
                    break;
                }

            }
        }
    }
}


//Funzinoe che esegue il cracking della password utilizzando la funzione di
//cifratura
void PDFCrack :: u_crack () {
    //Imposto la key a ukey
    key = u_key;
	//Come prima cosa verifico che la password sia diversa da nullptra
    if ( user_password() ) {
        u_found = true;
        user_pswd = false;
        u_password = "";
        return;
    }
    //Imposto la key
    for(unsigned i = 0; i < lenState; i++)
        key[i] = charSet[state[i]];
    for(unsigned i = lenState ; i < 32; i++)
        key[i] = pad[i-lenState];

    //Eseguo un ciclo finito che effettua il bruteforcing della chiave
    while ( !eos && !user_password () ) {
        /*cout << "current state: ";
        for(int i = 0; i < 5; i++)
            cout << state[i] << " ";
        cout << endl;
        cout << "  current key: ";
        for(int i = 0; i < 32; i++)
            printf("%x ",key[i]);
        cout << endl;*/
        SetNextPassword();
    }
    //Verifico se sono uscito dal ciclo a causa del ritrovamento della password
    if ( user_password() ) {
        u_found = true;
        user_pswd = true;
        u_password = GetCurrentPassword();
    }
}

void PDFCrack :: o_crack () {
    key = new uint8_t[sizeKey];
    for(unsigned i = 0; i < sizeKey; i++) {
        key[i] = o_key[i];
        key2[i] = o_key[i];
    }
	//Come prima cosa verifico che la password sia diversa da nullptra
    if ( owner_password() ) {
        o_found = true;
        o_password = "";
        return;
    }
    //Imposto la key
    for(unsigned i = 0; i < lenState; i++)
        key[i] = charSet[state[i]];
    for(unsigned i = lenState ; i < 32; i++)
        key[i] = pad[i-lenState];
    //Verifico se posso usare l'algoritmo veloce per il calcolo della owner_passwor
    //ovvero che la user password sia vuota
    if ( !user_pswd ) {
        //Eseguo un ciclo finito che effettua il bruteforcing della chiave
        while ( !eos && !owner_password () ) {
            SetNextPassword();
        }
        //Verifico se sono uscito dal ciclo a causa del ritrovamento della password
        if ( owner_password() ) {
            o_found = true;
            o_password = GetCurrentPassword();
        }
    } else {
        //Eseguo un ciclo finito che effettua il bruteforcing della chiave
        while ( !eos && !owner_password_nouser () ) {
            //Provo una chiave nota!
            SetNextPassword();
        }
        //Verifico se sono uscito dal ciclo a causa del ritrovamento della password
        if ( owner_password_nouser() ) {
            o_found = true;
            o_password = GetCurrentPassword();
        }
    }
}
//----------------------------------------------------------------------------//

//METODI RIGUARDANTI PDFCrackV1R2
//----------------------------------------------------------------------------//
bool PDFCrackV1R2 :: user_password () {
    md5(key,sizeKey,digest);                                  //Cifro la key con l'md5
    //Eseguo un test sui primi 4 caratteri
    Rc4_40( u_string , PARTIAL_TEST_SIZE , digest , tmp );    //Cifro la u_str con le 3 cifre prese prima
    //Devo ottenere in dec il pad
    for(int i = 0; i < PARTIAL_TEST_SIZE; i++)
        if(tmp[i] != pad[i])
            return false;
    //------------------------------------------------------------------------//
    //Test superato, proseguo con quello completo (prendendo solo i primi 5 caratteri dell'md5)
    Rc4_40( u_string , 32 , digest , tmp);    //Cifro la u_str con le 5 cifre prese prima
    //Devo ottenere in dec il pad
    for(int i = 0; i < 32; i++)
        if(tmp[i] != pad[i])
            return false;
    //Superato il test, la chiave Ã¨ quella giusta
    return true;
}

bool PDFCrackV1R2 :: owner_password () {
    //Cifro la password corrente con l'md5
    md5(key,32,digest);
    //Uso il risultato sopra come chiave per cifrare (RC4 a 40 bit) la o_string
    Rc4_40(o_string,32,digest,key2);
    //Effettuo un md5 sulla key2 (che contiene l'rc4 dell'md5 della password)
    md5(key2,sizeKey,digest);
    //VabbÃ¨... andiamo avanti cosÃ¬ insomma!
    Rc4_40(u_string,32,digest,tmp);
    //Verifico che ciÃ² che si trova nel tmp corrisponda al pad
    for(int i = 0; i < 32; i++)
        if( tmp[i] != pad[i] )
            return false;
    //Il controllo ha avuto successo! La password cercata Ã¨ corretta!
    return true;
}

//Reverse dell'algoritmo 3.4 (per cifrare la o_string) nel caso la user_password
//sia nullptra
bool PDFCrackV1R2 :: owner_password_nouser () {
    md5(key,32,digest);
    Rc4_40(o_string,32,digest,tmp);
    //Nella key2 dovrei ottenere il pad
    for(int i = 0; i < 32; i++)
        if( tmp[i] != pad[i] )
            return false;
    return true;
}
//----------------------------------------------------------------------------//

//METODI RIGUARDANTI PDFCrackV2R3
//----------------------------------------------------------------------------//
bool PDFCrackV2R3 :: user_password () {
    int i , j;
    //Cifro la key per ottenere cifr
    md5(key,sizeKey,digest);                //Cifro la key con l'md5
    md5_50(digest);                           //Cifro in md5 altre 50 volte (nel dubbio :D)
    //Eseguo un test sulle prime 3 cifre (per evitare di farlo tutto), se lo passa
    //eseguo il test completo
    for(i = 0; i < PARTIAL_TEST_SIZE; i++)
        tmp[i] = u_string[i];
    //Cifro con l'RC4 su 3 cifre
    for(i = 19; i >= 0; --i) {
        for(j = 0; j < length; ++j)
            tmpkey[j] = digest[j] ^ i;
        Rc4_128(tmp,PARTIAL_TEST_SIZE,tmpkey,tmp);
    }
    //Confronto il risultato atteso cifr con la user_pswd cifrata
    for(i = 0; i < PARTIAL_TEST_SIZE; i++)
        if(tmp[i] != opad[i])
            return false;
    //------------------------------------------------------------------------//
    //Il test precedente ha avuto buon esito, ora effettuo la verifica totale
    for(i = 0; i < 16; i++)
        tmp[i] = u_string[i];
    //Cifro con l'RC4 su tutte e 16 le cifre
    for(i = 19; i >= 0; --i) {
        for(j = 0; j < length; ++j)
            tmpkey[j] = digest[j] ^ i;
        Rc4_128(tmp,16,tmpkey,tmp);
    }
    //Confronto il risultato atteso cifr con la user_pswd cifrata
    for(i = 0; i < 16; i++)
        if(tmp[i] != opad[i])
            return false;
    //Test finale passato!
    return true;
}

bool PDFCrackV2R3 :: owner_password () {
    int a , b;
    //Effettuo una copia della key (mi serve :\)
    for(a = 0; a < 32; a++)
        key2[a] = key[a];
    //Cifro la padded-password con l'md5
    md5(key,32,digest);
    //Do altre 50 passate per sicurezza
    md5_50(digest);
    //Copio la o_string su tmp per poterla modificare
    for(a = 0; a < 32; a++)
        tmp[a] = o_string[a];
    //Cifro con l'RC4 su tutte e 16 le cifre
    for(a = 19; a >= 0; --a) {
        for(b = 0; b < length; ++b)
            tmpkey[b] = digest[b] ^ a;
        Rc4_128(tmp,32,tmpkey,tmp);
    }
    //in tmp dovrei ottenere la padded-password della V2R3
    for(a = 0; a < 32; a++)
        key[a] = tmp[a];
    //Verifico sia quella corretta
    if( user_password() ) {
        //Ripristino la copia della key
        for(a = 0; a < 32; a++)
            key[a] = key2[a];
        return true;
    } else {
        //ripristino la copia della key
        for(a = 0; a < 32; a++)
            key[a] = key2[a];
        return false;
    }
}

bool PDFCrackV2R3 :: owner_password_nouser () {
    int i, j;
    //Cifro la padded-password con l'md5
    md5(key,32,digest);
    //Do altre 50 passate per sicurezza
    md5_50(digest);
    //Copio la o_string su tmp per poterla modificare
    for(i = 0; i < 32; i++)
        tmp[i] = o_string[i];
    //Cifro con l'RC4 su 3 le cifre
    for(i = 19; i >= 0; --i) {
        for(j = 0; j < length; ++j)
            tmpkey[j] = digest[j] ^ i;
        Rc4_128(tmp,PARTIAL_TEST_SIZE,tmpkey,tmp);
    }
    for(i = 0; i < PARTIAL_TEST_SIZE; i++)
        if( tmp[i] != pad[i] )
            return false;
    //Tutto ok, faccio il controllo completo
    for(i = 19; i >= 0; --i) {
        for(j = 0; j < length; ++j)
            tmpkey[j] = digest[j] ^ i;
        Rc4_128(tmp,32,tmpkey,tmp);
    }
    for(i = 0; i < 32; i++)
        if( tmp[i] != pad[i] )
            return false;
    //Password corretta
    return true;
}
//----------------------------------------------------------------------------//
