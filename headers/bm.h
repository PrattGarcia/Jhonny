#ifndef BM_H
#define BM_H

#include<stdio.h>
#include<stdlib.h>
#include<stdbool.h>
#include<string.h>
#include "sha256.h"
#include "blowfish.h"
#include "aes.h"

#define AES		0x10		 
#define BLOWFISH	0x20 
#define KEY_256 	0x04
#define KEY_128		0x01
#define KEY_192		0x02 

BYTE conversion_bm(char *elemento);

bool validarCabeceraBm(BYTE bm); 

BYTE extraer_bm(BYTE bm);

int cant_Bm(BYTE bm);

#endif /* BM_H */
