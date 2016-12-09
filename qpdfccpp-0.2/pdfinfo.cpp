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

#include <iostream>
using namespace std;
#include <stdlib.h>

#include "pdfinfo.hpp"
//Per i test di verifica sulle chiavi di inizializzazione
#include "md5.hpp"
#include "rc4.hpp"

#define BUFFSIZE 256

static void
printHexString(vector<uint8_t> str) {
  for(int i=0;i<str.size();i++)
    printf("%x ",str[i]);
  printf("\n");
}


//  Definizioni di tutte le funzioni pubbliche della classe PDFInfo:
//  -Costruttori e distruttori
//  -Metodi che permettono l'output (PrintInfos)
//  -Funzioni pubbliche che richiamano altre funzioni private (LoadPdfInfos)
//  -Funzioni private

PDFInfo :: PDFInfo () : nomeFile(), is() {
    //Azzero tutti i puntatori
	infoPdf = nullptr;
	infoCrack = nullptr;
    //DEBUG INFOS
    verbose = 1;
    //Pulisco la memoria per la lettura del PDF
    clearPdfInfos ();

}

PDFInfo :: ~PDFInfo () {
    clearPdfInfos();
}

void PDFInfo :: PrintInfos () {
    uint8_t ch;
    if ( infoPdf ) {
        cout << "File name: " << nomeFile << " dimension: " << dimFile << " byte" << endl;
        cout << "PDF version "<< infoPdf->version_major << "." << infoPdf->version_minor << endl;

        if(ERRNOENCINFO != err ) {
            cout << "Security Handler: " << infoPdf->s_handler;
            cout << " version " << infoPdf->version << "." << infoPdf->revision << " length: " << infoPdf->length << endl;
            cout << "Permessi: " << infoPdf->permissions << endl;
            cout << "Encrypted Metadata: " << infoPdf->encryptMetaData << endl;
            cout << "FileID: ";
            for(unsigned i = 0; i < infoPdf->fileID.size(); i++) {
                ch = infoPdf->fileID[i];
                if(ch < 16)
                    printf("0%x", ch);
                else
                    printf("%x", ch);
            }
            cout << endl;

            cout << "user_string: ";
            for(unsigned i = 0; i < infoPdf->u_string.size(); i++) {
                ch = infoPdf->u_string[i];
                if(ch < 16)
                   printf("0%x", ch);
                else
                   printf("%x", ch);
            }
            cout << endl << "ownr_string: ";
            for(unsigned i = 0; i < infoPdf->o_string.size(); i++) {
                ch = infoPdf->o_string[i];
                if(ch < 16)
                    printf("0%x", ch);
                else
                    printf("%x", ch);
            }
            cout << endl;
        } else {
            cout << "No encryption infos!" << endl;
        }
    } else {
        cout << "No file loaded!" << endl;
    }
}

//Funzioni su file e stringhe (n.b. funzione esterna, non centra con la classe)
uint8_t hexToInt(const int b) {
    if(b >= '0' && b <= '9')
        return b-'0';
    else if(b >= 'a' && b <= 'f')
        return b-'a'+10;
    else if(b >= 'A' && b <= 'F')
        return b-'A'+10;
    else
        return 0;
}

//Parte della classe PDFSec che si occupa della lettura del file PDF e della
//ricerca delle informazioni contenute al suo interno. l'intera parte è privata
//e resa trasparente dalla funzione LoadPdfInfos ();

void PDFInfo :: LoadPdfInfos ( const string &n = "" ) {
    if( "" != n )
        nomeFile = n;
    //Apro il file in modalità binaria e determino se tutto è andato bene
    is.open(nomeFile.c_str(),ifstream::binary);
    if(!is.is_open())
        VERBOSE(1,"[PDFInfo::LoadPdfInfos()] ERRORE! File non valido o errore in apertura del file!")
    //Determino la dimensione totale del file
    VERBOSE(3,"[PDFInfo::LoadPdfInfos()] Determino la lunghezza del file: " << nomeFile)
    is.seekg(0, ios::end);
    dimFile = is.tellg();
    is.clear();
    is.seekg(0, ios::beg);
    VERBOSE(3,"[PDFInfo::LoadPdfInfos()] Lunghezza file: " << dimFile)
    //Pulisco la memoria
    if(!infoPdf) {
		VERBOSE(3,"[PDFInfo::LoadPdfInfos()] infoPdf != nullptr : pulisco la memoria")
        delete infoPdf;
    }
    infoPdf = new EncData;
    //Apro il file e verifico sia un pdf e recupero le info di cifratura
    err = readPdfFile();
    //Chiudo il file, non mi serve più!
    is.close();
}


int PDFInfo :: readPdfFile ( ) {
    int vers, subvers, ret;
    char * buffer = new char[BUFFSIZE];
    string buf;
    int pos_t;
    VERBOSE(3,"[PDFInfo::readFile()] Inizio scansione file...")
    //Recupero la prima linea del file
    is.getline(buffer, BUFFSIZE);
    buf = buffer;
    //Verifico che la prima linea del file sia l'intestazione di un PDF e ne leggo
    //la versione
    if( -1 != buf.find("%PDF-") ) {
        //Estraggo la versione nel formato "vers.subvers", esempio: "%PDF-1.4"
        vers = atoi(&buffer[5]);
        subvers = buf.find_first_of(".",6);
        subvers = atoi(&buffer[subvers+1]);
        //DEBUG
        //--------------------------------------------------------------------//
        VERBOSE(3,"[PDFInfo::readFile()] Trovato '%PDF-' - Version: " << vers << " Subversion: " << subvers)
        //--------------------------------------------------------------------//
        if( 0 <= vers && 0 <= subvers ) {
            infoPdf->version_major = vers;
            infoPdf->version_minor = subvers;
        }
        else
            return ERRVERS; //Versioni errate, probabilmente non è un PDF
    }
    else
        return ERRVERS;     //Il file non è un PDF
    //Mi sposto verso la fine del file ed eseguo la ricerca della sezione
    // "trailer\n<</Encrypt ... [<file_id><id>]>>"
    //DEBUG
    //------------------------------------------------------------------------//
    VERBOSE(3,"[PDFInfo::readFile()] Cerco il trailer...")
    //------------------------------------------------------------------------//
    is.seekg(-1024,ios::end);
    pos_t = findTrailer ();
    //DEBUG
    //------------------------------------------------------------------------//
    VERBOSE(3,"[PDFInfo::readFile()] Primo risultato (da eof-1024): " << pos_t)
    //------------------------------------------------------------------------//
    //Se non ho trovato il trailer, parto a cercarlo dall'inizio, per esser
    //sicuro di trovarlo
    if( pos_t < 0 ) {
        is.clear();
        is.seekg(0,ios::beg);
        pos_t = findTrailer ();
        //DEBUG
        //------------------------------------------------------------------------//
        VERBOSE(3,"[PDFInfo::readFile()] Seconda ricerca (dall'inizio): " << pos_t)
        //------------------------------------------------------------------------//
    }
    //Nel caso ci sia un errore, lo ritorno (o non c'è il trailer oppure manca qualcosa)
    if( pos_t < 0 )
        return pos_t;
    ret = getEncInfo ( pos_t );     //findEncryptObject(file,e_pos);
    //DEBUG
    //------------------------------------------------------------------------//
    if(ret)
        VERBOSE(2,"[PDFInfo::readFile()] Encrypted Info trovate!")
    else
        VERBOSE(2,"[PDFInfo::readFile()] Encrypted Info NON trovate!")
    //------------------------------------------------------------------------//
    if(!ret)
        return ERRNOENCINFO;

    return 0;
}


//  findTrailer
//  cerco la seguente stringa:
//  "trailer<</Encrypt ... [<file_id><id>]>>"
int PDFInfo :: findTrailer ( ) {
    int ch, pos_i, e_pos;
    bool encrypt = false;
    bool id = false;
    vector<uint8_t> str;
    string buf;
    //Scarto la fine della linea in corso (il trailer inizia con una nuova riga)
    //ATTENZIONE!!! NEL CASO IL FINE STRINGA SIA SOLTANTO 0x0A OPPURE 0x0D e non
    //TUTTI E DUE, L'ALGORITMO DA UN PROBLEMA
    //------------------------------------------------------------------------//
    getline(is,buf);
    //------------------------------------------------------------------------//
    while ( !is.eof() ) {
        getline(is,buf);
        if( -1 != buf.find("trailer",0) ) {
            VERBOSE(3,"[PDFInfo::findTrailer()] Trovato 'trailer', ora cerco '<<' sotto...")
            //Ho trovato il trailer, la prossima riga (dovrebbe) è la stringa
            //che contiene anche le informazioni di criptazione e inizia con "<<"
            //ATTENZIONE, ZONA CRUCIALE DA SCRIVERE CON MAGGIORI CONTROLLI!!!
            //----------------------------------------------------------------//
            do {
                getline(is,buf);
            } while( -1 == buf.find("<<",0) );
            //----------------------------------------------------------------//
            VERBOSE(3,"[PDFInfo::findTrailer()] Trovato '<<', cerco '/Encrypt'...")
            //Sono sulla stringa corretta, ricerco le info:
            //"/Encrypt 36 0 R" per esempio, dove 36 è la posizione che cerco (il resto non lo so!)
            pos_i = buf.find("/Encrypt",2);
            if( -1 != pos_i ) {
                //recupero il primo numero che trovo (è scritto malissimo, ma funziona)
                e_pos = atoi ( buf.substr( pos_i+8 , buf.find_first_of('/', pos_i + 8) - pos_i - 8 ).c_str() );
                if ( e_pos >= 0 )
                    encrypt = true;
                VERBOSE(3,"[PDFInfo::findTrailer()] Trovata posizione '/Encrypt': " << e_pos)
            }
            //"/ID [<...><...>]"
            pos_i = buf.find("/ID",2);
            if( -1 != pos_i ) {
                //estraggo la stringa racchiusa tra parentesi quadre
                int estr_inf = buf.find_first_of('[' , pos_i+3) + 1,
                    estr_sup = buf.find_first_of(']' , pos_i+64);
                str = parseID( buf.substr( estr_inf , estr_sup - estr_inf ) );
                if(!str.empty())
                    id = true;
                VERBOSE(3,"[PDFInfo::findTrailer()] Trovata posizione '/ID' del file")
            }
            if(encrypt && id) {
                infoPdf->fileID = str;
                return e_pos;
            }
        }
    }
    if(!encrypt && id)
        return ERRNOENCINFO;
    else if(!id && encrypt)
        return ERRNOFILEID;
    else {
        VERBOSE(2,"[PDFInfo::findTrailer()] Nessuna info di cifratura trovata!")
        return ERRNOINFOTRA;
    }
}

//Recupero l'ID del file "<...><...>" di 32 byte contenuto tra le prima parentesi
//acute
vector<uint8_t> PDFInfo :: parseID ( const string &str = "") {
    vector<uint8_t> ret;
    uint8_t buf[BUFFSIZE];
    int len = 0, i = 0;
    //Estraggo i primi 32 byte
    while(str[i] != '>' && len < BUFFSIZE && i < str.length() ) {
        if((str[i] >= '0' && str[i] <= '9') || (str[i] >= 'a' && str[i] <= 'f') || (str[i] >= 'A' && str[i] <= 'F')) {
            buf[len++] = str[i];
        }
        i++;
    }
    //Li converto in esadecimale
    for(unsigned j = 0, h = 0; j<len; j += 2) {
        ret.push_back(hexToInt(buf[j]) * 16);
        ret[h] += hexToInt(buf[j+1]);
        h++;
    }
    return ret;
}


bool PDFInfo :: getEncInfo ( const int e_pos ) {
    //DEBUG
    //------------------------------------------------------------------------//
    VERBOSE(3,"[PDFInfo::getEncInfo()] Posizione di ricerca: " << e_pos)
    //------------------------------------------------------------------------//
    //Converto l'intero in una stringa
    char * pos = new char[BUFFSIZE];
    char * buffer = new char[BUFFSIZE];
    string buf, temp;
    sprintf(pos,"%d",e_pos);
    int ch;
    //Riavvolgo il file per la ricerca
    is.clear();
    is.seekg(0,ios::beg);
    //Ricerco la posizione presente in e_pos
    //esempio di posizione e stringa: "8031 0 obj<<...>>"
    while ( !is.eof() ) {
        buf.clear();
        getline(is,buf);
        if( -1 != (ch = buf.find(pos,0)) ) {
            //DEBUG
            //------------------------------------------------------------------------//
            VERBOSE(3,"[PDFInfo::getEncInfo()] Posizione nel file: " << is.tellg() << " Colonna: "<< ch)
            //------------------------------------------------------------------------//
            //non necessariamente (ho parsato solo 3 file) il "<<" è sulla stessa
            //riga dell'e_pos e della stringa "obj" ma l'e_pos è all'inizio della riga
            //se identifichiamo il fine-riga come '0x0a', '0x0d' insieme o in alternativa

            //Verifico che i caratteri precedenti siano un 'a capo'
            if( 0 == ch || ( 0x0a == buf[ch-1] || 0x0d == buf[ch-1] ) ) {
                //Taglio tutta la stringa precedente a e_pos
                buf.erase(0,ch);
                temp = buf;
                //Ho identificato la riga che comincia per pos, carico tutto in
                //una stringa fino a "endobj"
                while( -1 == temp.find("endobj",0) ) {
                    getline(is,temp);
                    buf += temp;
                }
                //nel caso che abbia recuperato troppe righe (generatore PDF del cazzo)
                //taglio la stringa dal punto in cui comincia pos, fino a "endobj"
                buf.erase( buf.find("endobj",0) + 6 );
                //Faccio il parsing della stringa
                //"e_pos 0 obj<< ... >>endobj"
                //DEBUG
                //------------------------------------------------------------------------//
                VERBOSE(3,"[PDFInfo::getEncInfo()] Trovata stringa cifrata: " << buf.substr(0,35))
                //------------------------------------------------------------------------//
                return parseEncObject( buf );
            }
        }
    }
    return false;
}

bool PDFInfo :: parseEncObject ( const string &obj ) {
    int ch, i;
    bool fe = false,
         ff = false,
         fl = false,
         fo = false,
         fp = false,
         fr = false,
         fu = false,
         fv = false;
    vector<uint8_t> str;
    //I parametri da recuperare sono:
    //EncryptMetadata, Filter, Length (lunghezza sha-1)
    //O (owner_str), P (permessi), U (user_str), V (versione), R (revisione)

    //ATTENZIONE!!! DEBOLEZZA IN QUANTO NON CONTO SPAZI ULTERIORI A 1
    //------------------------------------------------------------------------//
    //EncryptMetadata
    if( -1 != (ch = obj.find("/EncryptMetadata",0)) ) {
        //Cerco il "false" esattamente uno spazio dopo
        if( -1 != obj.find("false", ch+17,10) ) {
            fe = true;
        }
    }
    //Filter
    //Esempio: "/Filter/Standard"
    if( -1 != (ch = obj.find("/Filter",0)) ) {
        ch = obj.find_first_of('/',ch+1);
        i = obj.find_first_of('/',ch+1) - ch - 1;
        if ( ch < ch + i ) {
            infoPdf->s_handler = obj.substr(ch+1,i);
            ff = true;
        }
    }
    //Lenght
    if ( -1 != (ch = obj.find("/Length",0)) ) {
        i = atoi ( obj.substr(ch+8,5).c_str() );
        if ( 0 < i ) {
            infoPdf->length = i;
            fl = true;
        }
    }
    //O (owner_str)
    if( -1 != (ch = obj.find("/O",0)) ) {
        //Riduco la stringa a "(...)" contenente la owner_str alla funzione per il parsing
        int start = obj.find_first_of('(',ch);
        int stop;
        for(int j = start; j < obj.length(); j++){
            if ( obj[j] == ')' && obj[j-1] != '\\' ) {
                stop = j+1;
                break;
            }
        }
        //converto la stringa contenuta tra parentesi in una stringa di byte
        str = stringToByte( obj.substr(start+1,stop-start-1) );
        if( !str.empty() ){
            if(str.size() != 32) {
                VERBOSE(1,"[PDFInfo::parseEncObject()] WARNING: O-String != 32 Bytes: " << str.size())
                wrn = WRNOSTR;
            }
            infoPdf->o_string = str;
            fo = true;
        }
    }
    //U (user_str)
    if( -1 != (ch = obj.find("/U",0)) ) {
        //Riduco la stringa a "(...)" contenente la owner_str alla funzione per il parsing
        int start = obj.find_first_of('(',ch);
        int stop;
        for(int j = start; j < obj.length(); j++){
            if ( obj[j] == ')' && obj[j-1] != '\\' ) {
                stop = j+1;
                break;
            }
        }
        //converto la stringa contenuta tra parentesi in una stringa di byte
        str = stringToByte( obj.substr(start+1,stop-start-1) );
        if( !str.empty() ){
            if(str.size() != 32) {
                VERBOSE(1,"[PDFInfo::parseEncObject()] WARNING: U-String != 32 Bytes: " << str.size())
                wrn = WRNUSTR;
            }
            infoPdf->u_string = str;
            fu = true;
        }
    }
    //P (permessi)
    if( -1 != (ch = obj.find("/P",0)) ) {
        //Acquisisco 11 caratteri massimi in quanto il maggior numero negativo è
        //composto da 10 numeri e il -
        infoPdf->permissions = atoi ( obj.substr(ch+3,11).c_str() );
        fp = true;
    }
    //V (versione)
    if( -1 != (ch = obj.find("/V",0)) ) {
        i = atoi ( obj.substr(ch+3,4).c_str() );
        if ( 0 < i ) {
            infoPdf->version = i;
            fv = true;
        }
    }
    //R (revision)
    if( -1 != (ch = obj.find("/R",0)) ) {
        i = atoi ( obj.substr(ch+3,4).c_str() );
        if ( 0 < i ) {
            infoPdf->revision = i;
            fr = true;
        }
    }
    //------------------------------------------------------------------------//
    if(!fe)
        infoPdf->encryptMetaData = true;
    if(!fl)
        infoPdf->length = 40;
    if(!fv)
        infoPdf->version = 0;

    if( infoPdf->s_handler != "Standard" )
        return true;

    return ff && fo && fp && fr && fu;
}


vector<uint8_t> PDFInfo :: stringToByte ( const string &s ) {
    unsigned i, j, l;
	uint8_t b, d;
	std::vector<uint8_t> tmp(s.length());
    vector<uint8_t> ret;

    for(i=0, l=0; i<s.length(); i++, l++) {
        b = s[i];
        if(b == '\\') {
            //We have reached a special character or the beginning of a octal
            //up to three digit number and should skip the initial backslash
            switch( s[++i] ) {
                case 'n':
                    b = 0x0a;
                    break;
                case 'r':
                    b = 0x0d;
                    break;
                case 't':
                    b = 0x09;
                    break;
                case 'b':
                    b = 0x08;
                    break;
                case 'f':
                    b = 0x0c;
                    break;
                case '(':
                    b = '(';
                    break;
                case ')':
                    b = ')';
                    break;
                case '\\':
                    b = '\\';
                    break;
                default:
                    if(s[i] >= '0' && s[i] < '8') {
                       d = 0;
                       for(j=0; i < s.length() && j < 3 &&
                         s[i] >= '0' && s[i] < '8' &&
                         (d*8)+(s[i]-'0') < 256; j++, i++) {
                           d *= 8;
                           d += (s[i]-'0');
                       }
                       //We need to step back one step if we reached the end of string
                       //or the end of digits (like for example \0000)
                       if(i < s.length() || j < 3) {i--;}
					   ret.push_back(d);
                    }
            }
        }
		tmp.at(l) = b;
    }
	for(unsigned i = 0; i < l-1; i++)
		ret.push_back(tmp.at((i)));
    return ret;
}

void PDFInfo :: initCracking ( const string &usr_pswd = "" ) {
    //Verifico che siano state trovate informazioni riguardo alla cifratura
    if( !infoPdf ) {
        VERBOSE(1,"[PDFInfo::initCracking()] File non presente!")
        return;
    } else if( ERRNOENCINFO == err ) {
        VERBOSE(1,"[PDFInfo::initCracking()] Non ci sono encryption info!")
        return;
    }
    //Pulisco la memoria
    clearWorkSpace();
    infoCrack = new EncWorkSpace;
    string userPswd = usr_pswd;
    //Stabilisco la versione della cifratura ed effettuo le operazioni preliminari:
    //-Verifico che i parametri in ingresso siano corretti
    //-Se esiste la user password, verifico che sia quella corretta
    //-Genero il dizionario per le password di bruteforcing
    //------------------------------------------------------------------------//

    /*--------------------------------------------------------------------------
    Standard di cifratura PDF:
    V:  0   Algoritmi non pubblicati e/o non più supportati
        1   RC4 a 40-bit con parole da 32 caratteri Latin-1                                 R: 2
        2   RC4 a lunghezza variabile tra 40 e 128 bit con parole da 32 caratteri Latin-1   R: 3
        3   Algoritmo non documentato con dimensione variabile tra 40 e 128 bit             R: 3
        4   Algoritmo che utilizza specifiche implementazioni (stronze)
    --------------------------------------------------------------------------*/

    //Riempio la chiave da cifrare
    // password_padded + o_string + permissions + fileID [ (se la revision è > 3) + encryptMetaData]
    vector<uint8_t> keyy;
    //Se c'è la user password la inserisco e la utilizzo
    if(usr_pswd != "") {
        infoCrack->user_pswd = true;
        if( 32 < userPswd.length())
            userPswd.erase(userPswd.begin()+32,userPswd.end());    //Se la password è superiore ai 32 caratteri, la taglio
        //Riempio la chiave di cifratura con la user_pswd
        for(unsigned i = 0; i < userPswd.length(); i++)
            keyy.push_back((uint8_t)userPswd[i]);
    } else
        infoCrack->user_pswd = false;

    for(unsigned i = 0; i < 32-userPswd.length(); i++)
        keyy.push_back(pad[i]);
    for(unsigned i = 0; i < 32; i++)
        keyy.push_back(infoPdf->o_string[i]);
    keyy.push_back(infoPdf->permissions & 0xff);
    keyy.push_back((infoPdf->permissions >> 8) & 0xff);
    keyy.push_back((infoPdf->permissions >> 16) & 0xff);
    keyy.push_back((infoPdf->permissions >> 24) & 0xff);
    for(unsigned i = 0; i < infoPdf->fileID.size(); i++)
        keyy.push_back(infoPdf->fileID[i]);
    if(infoPdf->revision > 3 && !infoPdf->encryptMetaData) {
        keyy.push_back(0xff);
        keyy.push_back(0xff);
        keyy.push_back(0xff);
        keyy.push_back(0xff);
    }
    //Copio i risultati sul vettore key (che utilizzerò per il cracking)
    infoCrack->u_key = keyy;
    //Genero la chiave da usare per la owner_password
    infoCrack->o_key = keyy;
    for(unsigned i = 0; i < 32; i++)
        infoCrack->o_key[i] = pad[i];
    //Copio le info dal pdf
    infoCrack->u_string = infoPdf->u_string;
    infoCrack->o_string = infoPdf->o_string;
    //Genero il vettore per il risultato dell'md5
    uint8_t * digest = new uint8_t[16];
    //Genero la chiave di test (diversa dal pad)
    //md5 ( pad + fileID )
    uint8_t * cifr = new uint8_t[32 + infoPdf->fileID.size()];
    for(unsigned i = 0; i < 32; i++)
        cifr[i] = pad[i];
    for(unsigned i = 0; i < infoPdf->fileID.size(); i++)
        cifr[32 + i] = infoPdf->fileID[i];
    md5(cifr,32 + infoPdf->fileID.size(),digest);
    for(int i = 0; i < 16; i++)
        infoCrack->own_pad.push_back(digest[i]);
    delete cifr;
    delete digest;
    //Copio i dati per stabilire il criterio di cracking
    infoCrack->length = infoPdf->length;
    infoCrack->V = infoPdf->version;
    infoCrack->R = infoPdf->revision;
    //DEBUG
    //------------------------------------------------------------------------//
    if(verbose >= 3) {
        VERBOSE(3,"[PDFInfo::initCracking()] Sequenza della key (cracking u_string):")
        printHexString(infoCrack->u_key);
    }
    //------------------------------------------------------------------------//
    //Come controllo finale, verifico che l'eventuale user_password fornita
    //sia corretta, altrimenti insulto l'utente e procedo con il cracking
    //della user_password
    if( infoCrack->user_pswd && (( infoPdf->revision == 2 && !userPasswordV1R2() ) ||
                      ( infoPdf->revision == 3 && !userPasswordV2R3() )) ) {
        VERBOSE(1,"[PDFInfo::initCracking()] WARNING: la user_password specificata non e' corretta! Re-initializing...")
		initCracking("");
    }
}

//Funzioni per la cifratura/decifratura delle varie versioni della user_password
bool PDFInfo :: userPasswordV1R2 () {
    VERBOSE(2,"[PDFInfo::userPasswordV1R2()] Verifico user_password!")
    //Genero i dati necessari al controllo
    uint8_t * digest = new uint8_t[16];
    uint8_t * key = new uint8_t[infoCrack->u_key.size()];
    uint8_t * u_string = new uint8_t[infoCrack->u_string.size()];
    uint8_t * tmp = new uint8_t[32];
    for(int i = 0; i < infoCrack->u_key.size(); i++)
        key[i] = infoCrack->u_key[i];
    for(int i = 0; i < infoCrack->u_string.size(); i++)
        key[i] = infoCrack->u_string[i];
    //Effettuo il controllo
    md5(key,infoCrack->u_key.size(),digest);                                  //Cifro la key con l'md5
    Rc4_40( u_string , 32 , digest , tmp);    //Cifro la u_str con le 5 cifre prese prima
    //Devo ottenere in dec il pad
    for(int i = 0; i < 32; i++)
        if(tmp[i] != pad[i])
            return false;
    //Superato il test, la chiave è quella giusta
    return true;
}

bool PDFInfo :: userPasswordV2R3 () {
    VERBOSE(2,"[PDFInfo::userPasswordV2R3()] Verifico user_password!")
    //Genero i dati necessari al controllo
    uint8_t * digest = new uint8_t[16];
    uint8_t * key = new uint8_t[infoCrack->u_key.size()];
    uint8_t * tmpkey = new uint8_t[infoCrack->length/8];
    uint8_t * tmp = new uint8_t[32];
    for(int i = 0; i < infoCrack->u_key.size(); i++)
        key[i] = infoCrack->u_key[i];
	for(int i = 0; i < 16; i++)
        tmp[i] = infoCrack->u_string[i];

    //Cifro la key per ottenere cifr
    md5(key,infoCrack->u_key.size(),digest);                //Cifro la key con l'md5
    md5_50(digest);                           //Cifro in md5 altre 50 volte (nel dubbio :D)
    //Cifro con l'RC4 su tutte e 16 le cifre
    for(int i = 19; i >= 0; --i) {
        for(int j = 0; j < infoCrack->length/8; ++j)
            tmpkey[j] = digest[j] ^ i;
        Rc4_128(tmp,16,tmpkey,tmp);
    }
    //Confronto il risultato atteso u_string con la pad cifrata
    for(int i = 0; i < 16; i++)
        if(tmp[i] != infoCrack->own_pad[i])
            return false;
    return true;
}


//Funzione che pulisce le zone di memoria utilizzate dalle funzioni di parsing
void PDFInfo :: clearPdfInfos () {
    VERBOSE(2,"[PDFInfo::clearPdfInfos()] Pulisco infoPdf!")
    //Elimino i dati caricati in memoria
    if(infoPdf) {
        infoPdf->s_handler.clear();
        infoPdf->o_string.clear();
        infoPdf->u_string.clear();
        infoPdf->fileID.clear();
        delete infoPdf;
		infoPdf = nullptr;
    }
    //Chiudo lo streaming da file (se non è già chiuso)
    if(is.is_open())
        is.close();
    //Azzero nomi e variabili varie
    err = 0;
    wrn = 0;
    dimFile = 0;
    nomeFile = "";
}

//Funzione che pulisce le zone di memoria utilizzate per la workspace
void PDFInfo :: clearWorkSpace () {
    VERBOSE(2,"[PDFInfo::clearWorkSpace()] Pulisco infoCrack!")
    if( infoCrack ) {
        infoCrack->u_key.clear();
        infoCrack->o_key.clear();
        infoCrack->o_string.clear();
        infoCrack->u_string.clear();
        infoCrack->own_pad.clear();
        delete infoCrack;
		infoCrack = nullptr;
    }
}
