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

#ifndef PDFCRACK_HPP
#define PDFCRACK_HPP

#include <cstring>
#include <vector>
#include <array>
#include <fstream>

#include <QThread>

#include "common.hpp"
#include "rc4.hpp"
#include "md5.hpp"


//Classe Padre per le varie classi di cracking
//implemento solo il caricamento delle informazioni base (previsto da tutti gli
//algoritmi di cifratura)
class PDFCrack : public QThread {
    public:
        //Funzioni pubbliche per la classe PDFCrack (specificate in PDFCrack.cpp)
        //Costruttori e distruttori
        PDFCrack ();
        virtual ~PDFCrack ();
        //Metodi SET per la modifica dei settaggi
        void SetWs ( EncWorkSpace );
        void SetCiphers ( int );        //Indica il numero di cifre che effettueranno le
                                        //combinazioni possibili
        void SetCharset ( const string );
        void SetState ( int , int * );
        //Metodi GET per verificare lo stato del cracking
        bool GetFoundUserPswd () { return u_found; }
        bool GetFoundOwnerPswd () { return o_found; }
        bool GetEnd () { return eos; }
        string GetUserPassword () { if(u_found) { return u_password; } else { return ""; } }
        string GetOwnerPassword () { if(o_found) { return o_password; } else { return ""; } }
        //Funzione per l'esecuzione
        void SetTypeCracking( bool type ) { own_usr = type; }
    protected:
        //Funzione che viene eseguita dal thread
        void run () { setPriority(QThread::HighPriority); if(own_usr) { u_crack(); } else { o_crack(); } }
        //Variabili della classe
        bool own_usr;               //Variabile di controllo sul tipo di forzatura:
                                    //-true: user
                                    //-false: owner
        //EncWorkSpace ws;
        bool u_found;             //Se la password viene trovata, verrà settato a true
        bool o_found;             //Se la password viene trovata, verrà settato a true
        string u_password;      //Nel caso venga trovata la passwod, verrà inserita qui
        string o_password;      //Nel caso venga trovata la passwod, verrà inserita qui
        //Variabili per la generazione veloce della key da cifrare
        uint8_t * charSet;      //Per l'ottimizzazione utilizzare una lista circolare
        int lenSet;
        unsigned numCifr;       //numero di cifre da combinare
        int * state;       //Stato dell'avanzamento
        unsigned lenState;
        bool eos;               //Stabilisce la fine delle password da cercare
        //Chiavi e variabili del cracking
        bool user_pswd;
        int length;
        uint8_t * o_key;
        uint8_t * u_key;
        int sizeKey;
        uint8_t * o_string;
        uint8_t * u_string;
        uint8_t * opad;
        uint8_t * digest;
        uint8_t * tmp;
        uint8_t * key;          //Puntatore alla chiave "corretta", quella che verrà
                                //Modificata e sulla quale si opererà per il crack
        //TEST
        uint8_t * key2;
        uint8_t * tmpkey;
        //METODI PRIVATI DELLA CLASSE
        void o_crack ();
        void u_crack ();
        void SetNextPassword ();
        string GetCurrentPassword ();
        //Metodi virtuali (da implementare nelle classi figlie)
        //Ad ogni implementazione verrà inserita la cifratura coerente
        virtual bool user_password () = 0;
        virtual bool owner_password () = 0;
        virtual bool owner_password_nouser () = 0;
};

//Classe figlia: V = 1 R = 2
class PDFCrackV1R2 : public PDFCrack {
    public:
        PDFCrackV1R2 () : PDFCrack() {}
        ~PDFCrackV1R2 () {}
    protected:
        //Funzioni con le cifrature della versione 1.2
        bool user_password ();
        bool owner_password ();
        bool owner_password_nouser ();
};


//Classe figlia: V = 2 R = 3
class PDFCrackV2R3 : public PDFCrack {
    public:
        PDFCrackV2R3 () : PDFCrack() {}
        ~PDFCrackV2R3 () {}
    protected:
        //Funzioni con le cifrature della versione 2.3
        bool user_password ();
        bool owner_password ();
        bool owner_password_nouser ();
};

#endif
