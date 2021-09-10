#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdbool.h>
#include <string.h>
#include <getopt.h>

#include "aes.h"
#include "bm.h"

bool dflag = false, kflag = false; //flags 

void print_help(char *command)
{
	printf("%s encripta o desincripta un archivo usando los algoritmos AES o BLOWFISH.\n", command+2);
	printf("uso:\n %s [-d] [-a<algo>] [-b<bits>] -k <passphrase> <nombre_archivo>\n", command);
	printf(" %s -h\n", command);
	printf("Opciones:\n");
	printf(" -h\t\t\tAyuda, muestra este mensaje\n");
	printf(" -d\t\t\tDesincripta el archivo en lugar de encriptarlo.\n");
	printf(" -k <passphrase>\t\tEspecifica la frase (passpgrase) de encriptación.\n");
	printf(" -a <algo>\t\tEspecifica el algoritmo de encriptación, opciones: aes, blowfish. [default: aes]\n"); 
	printf(" -b <bits>\t\tEspecifica los bits de encriptación, opciones: 128, 192, 256. [default: 128]\n");

}


void print_error(char *command) { 
	fprintf(stderr, "%s uso:\n", command+2);
	fprintf(stderr, "%s [-d] [-a <algo>] [-b <bits>] -k<passphrase> <nombre_archivo>\n", command);
	fprintf(stderr, "%s -h\n", command);
}

void print_hex(const BYTE* data, size_t size) {
	for(int i=0; i < size; ++i)	 
		printf("%02x", data[i]);
}

int main(int argc, char **argv)
{
	struct stat mi_stat;
	char *input_file = NULL;
	char *key_arg_str = NULL;
	char newFileName[150] = {0}; 
	int originalFile, newFile;
	int cant = 128;
	BYTE bitA = AES;
	BYTE cabecera = 0;
	BYTE hashing[SHA256_BLOCK_SIZE] = {0};
	BYTE *hashing_cant = NULL; 
	
	int opt, index; 
	unsigned long originalSize = 0;
	unsigned long fsize = 0;
	char *secretPhrase = NULL;

	while ((opt = getopt (argc, argv, "b:dha:k")) != -1){
		switch(opt)
		{
			case 'a':
				key_arg_str = optarg;		
				bitA = conversion_bm(key_arg_str); 
				break;
			case 'd':
				dflag = true;
				break;
			case 'h':
				print_help(argv[0]);
				return 0;
			case 'b':
				cant = atoi(optarg);
				break;
			case 'k':
				secretPhrase = optarg;
				kflag = true;
				break;
			case '?':
			default:
				print_error(argv[0]);
				return 1;
		}
	}
	if(cant == 128)
		cabecera = KEY_128;
	else if(cant == 256)
		cabecera = KEY_256;
	else if(cant == 192)
		cabecera = KEY_192;
	else{
		fprintf(stderr, "Error:\t'%d' no es una cantidad de bits válida.\n", cant);
		print_error(argv[0]);
		return 1;
	}
	
	if (!kflag) {
		fprintf(stderr, "Error:\tSe requiere una frase de encriptación.\n");
		print_error(argv[0]);
		return 1;
	}
	if (bitA == AES)
		cabecera = cabecera | bitA;
	else if (bitA == BLOWFISH)
		cabecera = cabecera | bitA; 
	else{
		fprintf(stderr, "Error:\t'%s' no es admitido como algoritmo.\n",key_arg_str); 
		print_error(argv[0]);
		return 1;
	}
	
	/* Aquí recoge argumentos que no son opción, por ejemplo el nombre del input file */
	for (index = optind; index < argc; index++)
		input_file = argv[index];

	if(!input_file){
		fprintf(stderr, "Especifique el nombre del archivo.\n");
		print_error(argv[0]);
		return 1;
	}
	if(stat(input_file, &mi_stat) < 0 ){
		fprintf(stderr, "Error:\tArchivo '%s'no encontrado.\n", input_file);
		return 1;
	}else{
		fsize = mi_stat.st_size;
		originalFile = open(input_file, O_RDONLY,0); 
	}
	SHA256_CTX ctx;
	sha256_init(&ctx);
	sha256_update(&ctx, (BYTE *)secretPhrase, strlen(secretPhrase));
	sha256_final(&ctx, hashing);
	hashing_cant = (BYTE*)calloc(SHA256_BLOCK_SIZE, sizeof(BYTE));
	memcpy(hashing_cant, hashing, cant/8);
	
	//Arreglo bytes clave de encriptación/desencriptación	
	BLOWFISH_KEY key_schedule_blowfish;
	WORD key_schedule[60];
	
	strcpy(newFileName, input_file);	
	
	//Buffer de encriptación/desencriptación
	BYTE aes_buffer[AES_BLOCK_SIZE] = {0};
	//Buffer de lectura, inicializado en cero
	BYTE read_buffer[AES_BLOCK_SIZE] = {0};
	
	if(dflag) {
		int ex = strlen(input_file) - 4;
		if(strcmp(input_file + ex, ".enc") != 0){
			fprintf(stderr, "Error:\tEl archivo '%s' debe contener la extensión .enc\n", input_file);
			print_error(argv[0]);
			return 1;
		}
		read(originalFile, &originalSize, 8);
		read(originalFile, &cabecera, 1); 	
		
		if(!validarCabeceraBm(cabecera)){
			fprintf(stderr, "Error:\tEL archivo '%s' contiene una cabecera inválida.\n", input_file);
			return 1;
		}		
		cant = cant_Bm(cabecera);
		bitA = extraer_bm(cabecera);
		memset(hashing_cant, 0, SHA256_BLOCK_SIZE);
		memcpy(hashing_cant, hashing, cant/8);
		originalSize = __bswap_64(originalSize),
		
		memset(newFileName + ex, 0, 4);
		newFile = open(newFileName, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
		long acumBytes = 0;
		
		if(bitA != BLOWFISH) {	
			printf("Usando algoritmo aes con %d bits...\n", cant);
			aes_key_setup(hashing_cant, key_schedule, cant);
			while(read(originalFile, aes_buffer, AES_BLOCK_SIZE)){
				aes_decrypt(aes_buffer, read_buffer, key_schedule, cant),
				acumBytes += AES_BLOCK_SIZE;
				if(acumBytes > originalSize)
					write(newFile, read_buffer, originalSize + AES_BLOCK_SIZE - acumBytes);
				else
					write(newFile, read_buffer, AES_BLOCK_SIZE);
				memset(read_buffer, 0, AES_BLOCK_SIZE);
				memset(aes_buffer, 0, AES_BLOCK_SIZE);
			}
		}else{
			printf("Usando algoritmo blowfish con %d bits...\n", cant);
			blowfish_key_setup(hashing_cant, &key_schedule_blowfish, cant);
			while(read(originalFile, aes_buffer, BLOWFISH_BLOCK_SIZE)){
				blowfish_decrypt(aes_buffer, read_buffer, &key_schedule_blowfish);
				acumBytes += BLOWFISH_BLOCK_SIZE;
				if(acumBytes > originalSize)
					write(newFile, read_buffer, originalSize +  BLOWFISH_BLOCK_SIZE - acumBytes);
				else
					write(newFile, read_buffer, BLOWFISH_BLOCK_SIZE);
				memset(read_buffer, 0, BLOWFISH_BLOCK_SIZE);
				memset(aes_buffer, 0, BLOWFISH_BLOCK_SIZE);	
			}
		}
		
		free(hashing_cant);
		close(originalFile);
		close(newFile);	
		printf("Archivo '%s' desencriptado exitosamente en '%s'.\n", input_file, newFileName);
		return 0;
	}
	
	//Encriptación
	strcat(newFileName, ".enc");
	newFile = open(newFileName, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
	originalSize = __bswap_64(fsize);
	write(newFile, &originalSize, 8);
	write(newFile, &cabecera, 1);

	if(bitA == AES) {
		printf("Usando algoritmo aes con %d bits...\n", cant);
		aes_key_setup(hashing_cant, key_schedule, cant);
		while(read(originalFile, aes_buffer, AES_BLOCK_SIZE)){
			aes_encrypt(aes_buffer, read_buffer, key_schedule, cant);
			write(newFile, read_buffer, AES_BLOCK_SIZE);
			memset(aes_buffer, 0, AES_BLOCK_SIZE);
			memset(read_buffer, 0, AES_BLOCK_SIZE);
		}
	}else{
		printf("Usando algoritmo blowfish  con %d bits...\n", cant);	
		blowfish_key_setup(hashing_cant, &key_schedule_blowfish, cant);
		while(read(originalFile, aes_buffer, BLOWFISH_BLOCK_SIZE)){ 
			blowfish_encrypt(aes_buffer, read_buffer, &key_schedule_blowfish);
			write(newFile, read_buffer, BLOWFISH_BLOCK_SIZE);
                        memset(aes_buffer, 0, BLOWFISH_BLOCK_SIZE);
                        memset(read_buffer, 0, BLOWFISH_BLOCK_SIZE); 
		}
	}
	printf("Archivo '%s' encriptado exitosamente en '%s'.\n", input_file, newFileName);
	free(hashing_cant);
	close(originalFile);
	close(newFile);
	return 0;
}


	
	

