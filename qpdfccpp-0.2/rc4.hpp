#ifndef RC4_H
#define RC4_H

#include <stdint.h>
#include <string.h>

// Rc4 ( testo , dimTesto , chiave , dimChiave , testoCifrato )

//La funzione è particolarmente ottimizzata (e in parte accoppiata) per aumentare
//l'efficienza della cifratura.
void Rc4 ( const uint8_t * pszText , unsigned sizeText ,
            const uint8_t * pszKey , unsigned sizeKey ,
            uint8_t * ret );

//Versioni dell'algoritmo precedenti con il ciclo iniziale srotolato in parte
//per aumentarne le prestazioni

//Funzione ottimizzata rispetto a quella superiore per eseguire l'RC4 con una chiave
//da 40 bit (5 caratteri)
void Rc4_40 ( const uint8_t * pszText , unsigned sizeText ,
            const uint8_t * pszKey , uint8_t * ret );

//Funzione ottimizzata rispetto a quella superiore per eseguire l'RC4 con una chiave
//da 128 bit (32 caratteri)
void Rc4_128 ( const uint8_t * pszText , unsigned sizeText ,
            const uint8_t * pszKey , uint8_t * ret );

#endif
