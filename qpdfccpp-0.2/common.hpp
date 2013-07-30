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

#include <stdint.h>
#include <vector>
#include <cstring>
using namespace std;

#ifndef COMMON_HPP
#define COMMON_HPP

//Definizione degli errori:
//----------------------------------------------------------------------------//
//Errori nel parsing
#define ERRNOFILE       -1      //Non esiste il file specificato
#define ERRVERS         -2      //Versione del file non supportata
#define ERRNOENCINFO    -3      //Oggetto EncInfo non trovato nel file, errore/nessuna criptazione
#define ERRNOFILEID     -4      //Trailer: FileID Object non trovato
#define ERRNOINFOTRA    -5      //Trailer non trovato
//----------------------------------------------------------------------------//
//Definizione dei warning:
//----------------------------------------------------------------------------//
#define WRNOSTR         -1      //Dimensione della owner_string diversa da 32 byte
#define WRNUSTR         -2      //Dimensione della user_string diversa da 32 byte
//----------------------------------------------------------------------------//
//Definizione di variabili di controllo
#define USER            true
#define OWNER           false
//MACRO per il debugging
//----------------------------------------------------------------------------//
//la variabile verbose è un intero contenente un numero da 0 a 3
//(se più alto non ha senso, viene preso come uguale a 3)
//e in base al suo valore abilita/disabilita messaggi da console per il
//debug.
//- 0 : nessun messaggio di output su STDOUT e su STDERR
//- 1 : messaggi di output per gli errori su STDERR (default)
//- 2 : output minimo per conferma dei vari passaggi (macro operazioni)
//- 3 : output dettagliato su ogni operazione eseguita dal programma
#define VERBOSE(a,b)    if ( verbose >= a ) { cout << b << endl; }
//----------------------------------------------------------------------------//



#define STD_CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
#define STD_EXT_CHARSET "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890.,:;-_<>@#§+*[]^'?=)(/&%$£\"!|\\"

/**
    EncData holds all the information regarding the encryption-setting of a
    specific pdf.
    s_handler - Security handler string.
    o_string - Owner-string, 32 bytes
    u_string - User-string, 32 bytes
    fileID
*/

//Dati da estrarre dal file PDF
struct EncData {
    string s_handler;
    vector<uint8_t> o_string;
    vector<uint8_t> u_string;
    vector<uint8_t> fileID;
    bool encryptMetaData;
    unsigned int version_major;
    unsigned int version_minor;
    int length;
    int permissions;
    int revision;
    int version;
};

//Dati inizializzati per il cracking
struct EncWorkSpace {
    bool user_pswd;
    int length;
    int V;
    int R;
    vector<uint8_t> u_key;
    vector<uint8_t> o_key;
    vector<uint8_t> o_string;
    vector<uint8_t> u_string;
    vector<uint8_t> own_pad;
};

//Costanti di cifratura per inizializzare i vari algoritmi di cifratura
const uint8_t pad[] = {
  0x28,0xBF,0x4E,0x5E,0x4E,0x75,0x8A,0x41,
  0x64,0x00,0x4E,0x56,0xFF,0xFA,0x01,0x08,
  0x2E,0x2E,0x00,0xB6,0xD0,0x68,0x3E,0x80,
  0x2F,0x0C,0xA9,0xFE,0x64,0x53,0x69,0x7A
};


#endif
