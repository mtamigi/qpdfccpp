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

#ifndef PDFINFO_HPP
#define PDFINFO_HPP

#include <cstring>
#include <vector>
#include <fstream>

#include "common.hpp"

class PDFInfo {
    public:
        //Funzioni pubbliche per la classe PDFSec (specificate in PDFSec.cpp)
        //Costruttori e distruttori
        PDFInfo ();
        ~PDFInfo ();
        //Funzioni per la shell da sostituire a parametri pubblici
        void PrintInfos ();
        //Funzioni primarie
        void LoadPdfInfos ( const string );
        void initCracking ( const string ); //Gli passo la user_password (se la conosco)
        //Metodi SET e GET
        inline void SetFile ( const string file ) { nomeFile = file; }
        inline string GetFile () { return nomeFile; }
        inline unsigned GetDimFile () { return dimFile; }
        inline int GetErr () { return err; }
        inline int GetWrn () { return wrn; }
        EncData GetPdfInfos () { return *infoPdf; }
        EncWorkSpace GetCrackWorkSpace () { return *infoCrack; }
        //DEBUG INFOS
        //--------------------------------------------------------------------//
        //la variabile verbose è un intero contenente un numero da 0 a 3
        //(se più alto non ha senso, viene preso come uguale a 3)
        //e in base al suo valore abilita/disabilita messaggi da console per il
        //debug.
        //- 0 : nessun messaggio di output su STDOUT e su STDERR
        //- 1 : messaggi di output per gli errori su STDERR (default)
        //- 2 : output minimo per conferma dei vari passaggi (macro operazioni)
        //- 3 : output dettagliato su ogni operazione eseguita dal programma
        unsigned verbose;
        //--------------------------------------------------------------------//
    private:
        //VARIABILI
        //--------------------------------------------------------------------//
        string nomeFile;
        unsigned dimFile;
        //Variabili per il parsing e il mantenimento delle info sul file
        EncData * infoPdf;
        ifstream is;
        int err;
        int wrn;
        //Variabili per la generazione dell'ambiente di cracking
        EncWorkSpace * infoCrack;
        //--------------------------------------------------------------------//
        //METODI
        //--------------------------------------------------------------------//
        //Funzioni per la lettura del PDF (funzioni specificate in PDFParser.cpp)
        //Completate e (apparentemente) funzionanti! (rifatte da pdfcrack-0.11)
        int readPdfFile ();
        int findTrailer ();
        vector<uint8_t> parseID ( const string );
        bool getEncInfo ( const int );
        bool parseEncObject ( const string );
        vector<uint8_t> stringToByte ( const string );
        void clearPdfInfos ();
        //Funzioni per la generazione del WorkSpace di cracking dei PDF
        bool userPasswordV1R2();
        bool userPasswordV2R3();
        void clearWorkSpace ();
};


#endif
