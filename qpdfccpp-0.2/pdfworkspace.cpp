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


//DEBUG
#include <iostream>
#include <time.h>
using namespace std;

#include "pdfworkspace.hpp"


PDFWorkspace :: PDFWorkspace () {
     crack = NULL;
     stato = new int[32];
     lenStato = 0;
     max = 0;
     found = false;
}

PDFWorkspace :: ~PDFWorkspace () {
    if( crack )
        delete [] crack;
    delete [] stato;
}

void PDFWorkspace :: SetWs ( EncWorkSpace enc , unsigned _min = 1 ,
                             unsigned _max = 5 , string chs = STD_CHARSET, bool tp = USER ) {
    //Imposto l'ambiente del thread:
    setPriority(QThread::LowPriority);
    //Copio l'impostazione inserita e predispondo il sistema per partire
    //-Genero le classi con i parametri di cifratura corretti
    encWs = enc;
    usr_own = tp;
    //Eseguo i settaggi e le allocazioni base
    if( enc.V == 1 && enc.R == 2  )
        crack = new PDFCrackV1R2[cores];
    else if ( enc.V == 2 && enc.R == 3  )
        crack = new PDFCrackV2R3[cores];
    else
        cores = 0;
    //Carico le informazioni iniziali per ogni thread (comuni a tutte)
    for(unsigned i = 0; i < cores; i++) {
        crack[i].SetWs(enc);
        crack[i].SetCharset(chs);
        crack[i].SetTypeCracking(tp);
    }
    //Genero il vettore di stato
    for(unsigned i = 0; i < 32; i++)
        if( i < _min )
            stato[i] = 0;
        else
            stato[i] = -1;
    lenStato = _min;
    max = _max;
    min = _min;
    lenCs = chs.size();
}

void PDFWorkspace :: SetNextStatus () {
    //cout << "WS[SetNextStatus()]: max = " << max << " | lenStato = " << lenStato << endl;
    //Determino la combinazione successiva
    if ( ++stato[lenStato] >= lenCs ) {
        stato[lenStato++] = 0;
        if( lenStato < max )
            stato[lenStato] = 0;
    }
    //Se è corretta azzero, altrimenti blocco tutto
    if(lenStato == max)
        ciclo = true;       //Ho finito le combinazioni, termino il ciclo
}

void PDFWorkspace :: run () {
    time_t start, stop;
    cout << "[run()] Start cracking..." << endl;
    start = clock();
    ciclo = false;
    found = false;
    //Ciclo costantemente per vedere se qualche thread ha finito.
    //In caso affermativo verifico se ha trovato la password (nel caso termino tutto)
    //altrimenti lo riavvio con la successiva sequenza di dati da elaborare.
    int i = 0;
    while ( !ciclo ) {
        msleep(100);
        if ( !crack[i].isRunning() ) {
            //Il thread è fermo, verifico se è stata trovata una password
            if ( crack[i].GetFoundOwnerPswd() || crack[i].GetFoundUserPswd() ) {
                if(crack[i].GetFoundOwnerPswd())
                    pswd = crack[i].GetOwnerPassword();
                else
                    pswd = crack[i].GetUserPassword();
                found = true;
                ciclo = true;
                //Fermo tutti altri thread
                for(unsigned j = 0; j < cores; j++)
                    crack[j].terminate();
            } else {
                //Riavvio il thread con i parametri successivi
                crack[i].SetCiphers(lenStato);
                crack[i].SetState(lenStato,stato);
                crack[i].start();
                //Genero un nuovo stato
                SetNextStatus();
            }
        }
		if (cores)  //Incremento circolarmente il contatore
		   i = ++i % cores;
    }
    stop = clock();
    cout << "[run()] End: time: " << (stop-start) << " msec" << endl;
    emit End( usr_own , found , pswd.c_str() );
}
