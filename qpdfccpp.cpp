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

#include "qpdfccpp.h"
#include "ui_qpdfccpp.h"

#include <QFileDialog>
#include <QMessageBox>
#include <QThread>

qpdfccpp :: qpdfccpp (QWidget *parent) : QMainWindow(parent), ui(new Ui::qpdfccpp) {
    path = QDir::homePath();
    ui->setupUi(this);
    //Setto il funzionamento di tutti i pulsanti
    connect(ui->pushButton,SIGNAL(clicked()),this,SLOT(OpenFile()));
    connect(ui->pushButton_2,SIGNAL(clicked()),this,SLOT(crackUserPswd()));
    connect(ui->pushButton_3,SIGNAL(clicked()),this,SLOT(crackOwnerPswd()));
    //Setto i parametri default dell'interfaccia
    //I numeri del minimo e del massimo di caratteri usati nella crack
    ui->spinBox->setRange(1,32);
    ui->spinBox->setValue(3);
    ui->spinBox_2->setRange(1,32);
    ui->spinBox_2->setValue(6);
    //Setto i parametri dell'applicazione prendendo le informazioni dal sistema operativo
    cores = QThread::idealThreadCount ();
    ui->spinBox_3->setRange(1,cores);
    ui->spinBox_3->setValue(cores/2);
}

qpdfccpp::~qpdfccpp() {
    delete ui;
    if(crack)
        delete [] crack;
}

void qpdfccpp::OpenFile() {
    EncData inf;
    QString fileName;
    QString s;
    QString file = QFileDialog::getOpenFileName(this, tr("Open File"),
                                                     path,
                                                     tr("Files (*.pdf)"));

    //Per il debug veloce
    //QString file = "C:\\Users\\Matteo Tamiei\\Desktop\\PDF\\pdfccpp-0.4.1\\file_000_000.pdf";
    //Se non immetto alcun file, annullo tutto ed esco
    if( file == "" ) {
        ui->lineEdit->setText("");
        ui->label_2->setText("Version:");
        ui->label_3->setText("Size:");
        ui->textBrowser->setText("");
        ui->pushButton_2->setEnabled(false);
        ui->pushButton_3->setEnabled(false);
        ui->lineEdit_5->setEnabled(false);
        ui->lineEdit_6->setEnabled(false);
        return;
    }
    //Separo il nome del file dal percorso della cartella
    int ind1 = 0, ind2 = 0;
    while ( ind1 != -1 ) {
        ind2 = ind1 + 1;
        //ATTENZIONE!!!
        ind1 = file.indexOf('/',ind2);
    }
    //Setto la directory di partenza per la nuova ricerca del file,
    //come la directory dove sono appena stato e pongo il nome del file
    //nella textbox
    path = file;
    path.remove(ind2,file.length());
    fileName = file;
    fileName.remove(0,ind2);
    ui->lineEdit->setText(fileName);
    //Da qui inserisco direttamente la lettura e l'acquisizione del file
    //in quanto non è molto onerosa e fornisce informazioni immediatamente
    pdf.LoadPdfInfos(file.toStdString());
    inf = pdf.GetPdfInfos();
    //Pubblico tutte le informazioni reperite
    ui->label_2->setText("Version: " + s.number(inf.version_major) + "." + s.number(inf.version_minor));
    ui->label_3->setText("Size: " + s.number(pdf.GetDimFile()) + " byte");
    if( pdf.GetErr() == ERRVERS ) {
        ui->textBrowser->setText("Version not supporting!");
        ui->pushButton_2->setEnabled(false);
        ui->pushButton_3->setEnabled(false);
        ui->lineEdit_5->setEnabled(false);
        ui->lineEdit_6->setEnabled(false);
    }
    else if ( pdf.GetErr() == ERRNOENCINFO || pdf.GetErr() == ERRNOFILEID || pdf.GetErr() == ERRNOINFOTRA) {
        ui->textBrowser->setText("There are no security information!");
        ui->pushButton_2->setEnabled(false);
        ui->pushButton_3->setEnabled(false);
        ui->lineEdit_5->setEnabled(false);
        ui->lineEdit_6->setEnabled(false);
    } else {
        QString fid, ustr, ostr, mtdt;
        for(unsigned i = 0; i < inf.fileID.size(); i++) {
            fid.append(fid.number(inf.fileID[i],16));
        }
        for(unsigned i = 0; i < inf.u_string.size(); i++) {
            ustr.append(ustr.number(inf.u_string[i],16));
        }
        for(unsigned i = 0; i < inf.o_string.size(); i++) {
            ostr.append(ostr.number(inf.o_string[i],16));
        }
        if( inf.encryptMetaData == 0 )
            mtdt = "false";
        else
            mtdt = "true";
        ui->textBrowser->setText("Security handler: " + s.fromStdString(inf.s_handler) + "\n" +
                                 "Version: " + s.number(inf.version) + "." + s.number(inf.revision) + "\n" +
                                 "Length: " + s.number(inf.length) + "\n"
                                 "Permissions: " + s.number(inf.permissions) + "\n"
                                 "Encrypted metadata: " + mtdt + "\n"
                                 "File ID: " + fid + "\n"
                                 "User string: " + ustr + "\n"
                                 "Owner string: " + ostr );
        ui->pushButton_2->setEnabled(true);
        ui->pushButton_3->setEnabled(true);
        ui->lineEdit_5->setEnabled(false);
        ui->lineEdit_5->setText("");
        ui->lineEdit_6->setEnabled(false);
        ui->lineEdit_6->setText("");

        pdf.initCracking("");
    }
}

void qpdfccpp::crackUserPswd () {
    string chs;
    //pdf.initCracking("");
    //Verifico che charset usare:
    if(ui->radioButton->isEnabled())
        chs = STD_CHARSET;
    else if (ui->radioButton_2->isEnabled())
        chs = STD_EXT_CHARSET;
    else if (ui->radioButton_3->isEnabled())
        chs = ui->label_4->text().toStdString();
    else
        return;
    //-------------------------------------------------------------------------//
    //Genero il workspace con i vari thread
    //--------------------------------------------------------------------------//
    ws = new PDFWorkspace();
    ws->SetCores(ui->spinBox_3->value());
    ws->SetWs(pdf.GetCrackWorkSpace(),      //Informazioni di cifratura
             ui->spinBox->value(),         //min
             ui->spinBox_2->value(),       //max
             chs,                          //CHARSET
             USER);                        //USER/OWNER
    //Imposto il segnale di fine del cracking
    connect(ws,SIGNAL(End(bool,bool,const char*)),this,SLOT(showResults(bool,bool,const char*)));
    //Imposto il segnale che scandisce lo step di avanzamento
    //connect(ws,SIGNAL(NextStep(unsigned),this,SLOT(setNextStep(unsigned)));
    ws->start();
    //--------------------------------------------------------------------------//
    //Disabilito tutti i controlli
    ui->pushButton->setEnabled(false);
    ui->pushButton_2->setEnabled(false);
    ui->pushButton_3->setEnabled(false);
    ui->spinBox->setEnabled(false);
    ui->spinBox_2->setEnabled(false);
    ui->spinBox_3->setEnabled(false);
    ui->radioButton->setEnabled(false);
    ui->radioButton_2->setEnabled(false);
    ui->radioButton_3->setEnabled(false);
}


void qpdfccpp::crackOwnerPswd () {
    string chs;
    //Inizializzo il cracking con la password (se è presente)
    //pdf.initCracking(ui->lineEdit_6->text().toStdString());
    //Verifico che charset usare:
    if(ui->radioButton->isEnabled())
        chs = STD_CHARSET;
    else if (ui->radioButton_2->isEnabled())
        chs = STD_EXT_CHARSET;
    else if (ui->radioButton_3->isEnabled())
        chs = ui->label_4->text().toStdString();
    else
        return;
    //-------------------------------------------------------------------------//
    //Genero il workspace con i vari thread
    //--------------------------------------------------------------------------//
    ws = new PDFWorkspace();
    ws->SetCores(ui->spinBox_3->value());
    ws->SetWs(pdf.GetCrackWorkSpace(),      //Informazioni di cifratura
             ui->spinBox->value(),         //min
             ui->spinBox_2->value(),       //max
             chs,                           //CHARSET
             OWNER);                        //USER/OWNER
    //Imposto il segnale di fine del cracking
    connect(ws,SIGNAL(End(bool,bool,const char*)),this,SLOT(showResults(bool,bool,const char*)));
    //Imposto il segnale che scandisce lo step di avanzamento
    //connect(ws,SIGNAL(NextStep(unsigned),this,SLOT(setNextStep(unsigned)));
    ws->start();
    //--------------------------------------------------------------------------//
    //Disabilito tutti i controlli
    ui->pushButton->setEnabled(false);
    ui->pushButton_2->setEnabled(false);
    ui->pushButton_3->setEnabled(false);
    ui->spinBox->setEnabled(false);
    ui->spinBox_2->setEnabled(false);
    ui->spinBox_3->setEnabled(false);
    ui->radioButton->setEnabled(false);
    ui->radioButton_2->setEnabled(false);
    ui->radioButton_3->setEnabled(false);
}

void qpdfccpp :: showResults ( bool us_ow , bool found , const char * pass ) {
    QMessageBox msg;
    string password = string(pass);
    if( found ) {
        if ( us_ow == USER ) {
            ui->lineEdit_5->setText(QString(password.c_str()));
            ui->lineEdit_5->setEnabled(true);
            msg.setText("Found user_password: '"+QString(password.c_str())+"'");
            msg.exec();
        } else if ( us_ow == OWNER ) {
            ui->lineEdit_6->setText(QString(password.c_str()));
            ui->lineEdit_6->setEnabled(true);
            msg.setText("Found owner_password: '"+QString(password.c_str())+"'");
            msg.exec();
        }
    }
    else {
        msg.setText("Password not found!");
        msg.exec();
    }
    //Elimino la connessione
    disconnect(ws,SIGNAL(End(bool,bool,const char*)),this,SLOT(showResults(bool,bool,const char*)));
    //Abilito nuovamente tutti i controlli necessari:
    ui->pushButton->setEnabled(true);
    ui->pushButton_2->setEnabled(true);
    ui->pushButton_3->setEnabled(true);
    ui->spinBox->setEnabled(true);
    ui->spinBox_2->setEnabled(true);
    ui->spinBox_3->setEnabled(true);
    ui->radioButton->setEnabled(true);
    ui->radioButton_2->setEnabled(true);
    ui->radioButton_3->setEnabled(true);
    delete ws;
}
