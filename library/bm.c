#include "bm.h"

BYTE conversion_bm(char *elemento) {
	if (strcmp(elemento, "aes") == 0) {	
		return AES;
	}else if (strcmp(elemento, "blowfish") == 0) {
		return BLOWFISH;
	}
	return 0;
}

bool validarCabeceraBm(BYTE bm){
	BYTE elemento = bm & 0x30;
	BYTE cant = bm & 0x07;
	
	if((elemento != AES) && (elemento != BLOWFISH))
		return false;
	if((cant != KEY_192) && (cant != KEY_128) && (cant != KEY_256))
		return false;
	if((bm & 0xc8) != 0)
		return false;
	return true;
}

BYTE extraer_bm(BYTE bm){
	bm = bm & 0x30;
	switch(bm) {
		case AES:
			return AES;
		case BLOWFISH:
			return BLOWFISH;
		default:
			return 0; 
	}	
}

int cant_Bm(BYTE bm) {
	bm = bm & 0x07;
	switch(bm){
		case KEY_192:
			return 192;
		case KEY_128:
			return 128;
		case KEY_256:	 
			return 256;
		default: 
			return -1;
	}
}
