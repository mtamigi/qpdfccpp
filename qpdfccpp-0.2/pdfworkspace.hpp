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


#ifndef PDFWORKSPACE_HPP
#define PDFWORKSPACE_HPP

#include "pdfcrack.hpp"
#include <string>
#include <QThread>
//#include <QObject>
using namespace std;

namespace Ui {
    class PDFWorkspace;
}

//Questa classe prende in consegna le informazioni a monte (PDFInfo) e pianifica
//il cracking su più core della CPU in base ai thread disponibili.

class PDFWorkspace : public QThread {
    Q_OBJECT

    public:
        //Funzioni pubbliche per la classe PDFSec (specificate in PDFWorkspace.cpp)
        //Costruttori e distruttori
        PDFWorkspace (); /* {crack = NULL;
                         stato = new int[32];
                         lenStato = 0;
                         max = 0;
                         found = false;}*/
        ~PDFWorkspace ();
        //Funzioni SET e GET
        void SetWs ( EncWorkSpace , unsigned , unsigned , string , bool );
        void SetCores ( unsigned c ) { cores = c; }
        void SetNextStatus ();
        //Funzioni per il debugging
        EncWorkSpace GetWs () { return encWs; }
        unsigned GetCores () { return cores; }
        bool GetFound () { return found; }
        string GetPassword () { return pswd; }
    signals:
        void End ( bool , bool , const char * );
        //void NextStep ( unsigned );
    private:
        EncWorkSpace encWs;
        bool usr_own;
        unsigned cores;
        PDFCrack * crack;
        int * stato;
        int lenStato;
        int lenCs;
        int max, min;
        bool ciclo;
        //Variabili dell'output
        string pswd;
        bool found;
        //Funzione di esecuzione del cracking
        void run ();
};


#endif // PDFWORKSPACE_HPP
