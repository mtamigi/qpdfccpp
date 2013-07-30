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

#ifndef QPDFCCPP_H
#define QPDFCCPP_H

#include <QMainWindow>
#include "qpdfccpp-0.2/pdfInfo.hpp"
#include "qpdfccpp-0.2/pdfCrack.hpp"
#include "qpdfccpp-0.2/pdfworkspace.hpp"

namespace Ui {
class qpdfccpp;
}

class qpdfccpp : public QMainWindow {
        Q_OBJECT
    
    public:
        explicit qpdfccpp(QWidget *parent = 0);
        ~qpdfccpp();
    //Inserisco tutti gli slots
    public slots:
        void OpenFile ();
        void crackUserPswd ();
        void crackOwnerPswd ();
        void showResults ( bool , bool , const char * );
        //void setNextStep ( unsigned );
    private:
        //Variabili per l'uso dell'interfaccia
        Ui::qpdfccpp *ui;
        QString path;
        //Variabili per il WorkSpace
        int cores;      //Numero di core del processore da poter utilizzare
                        //scalabili e selezionabili dall'utente
        //Variabili per la gestione e cracking dei PDF
        PDFInfo pdf;
        PDFCrack * crack;
        PDFWorkspace * ws;

};

#endif // QPDFCCPP_H
