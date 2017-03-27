#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif


/**
 * Encrypt or decrypt, depending on flag 'should_encrypt'
 */
void crypt(int should_encrypt, FILE *ifp, FILE *ofp, unsigned char *ckey, unsigned char *ivec) 
{
	const unsigned BUFSIZE = 4096;
	unsigned char *read_buf = malloc(BUFSIZE);
	unsigned char *cipher_buf;
	unsigned blocksize;
	int out_len;
	EVP_CIPHER_CTX ctx;

	EVP_CipherInit(&ctx, EVP_aes_128_cbc(), ckey, ivec, should_encrypt);
	blocksize = EVP_CIPHER_CTX_block_size(&ctx);
	cipher_buf = malloc(BUFSIZE + blocksize);

	while(1)
	{
		// Read in data in blocks until EOF. Update the ciphering with each read.

		int numRead = fread(read_buf, sizeof(unsigned char), BUFSIZE, ifp);
		EVP_CipherUpdate(&ctx, cipher_buf, &out_len, read_buf, numRead);
		fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);
		if (numRead < BUFSIZE) { // EOF
			break;
		}
	}

	// Now cipher the final block and write it out.

	EVP_CipherFinal(&ctx, cipher_buf, &out_len);
	fwrite(cipher_buf, sizeof(unsigned char), out_len, ofp);

	// Free memory

	free(cipher_buf);
	free(read_buf);
}

int main(int argc, char *argv[]) 
{
	unsigned char ckey[] = "thiskeyisverybad";
	unsigned char ivec[] = "dontusethisinput";
	FILE *fIN, *fOUT;

	//argv[0] for encrypt or decrypt
	//argv[1] for input file
	//argv[2] for output file
	if(argc <= 3)
	{
		fprintf(stderr, "Usage: %s <enc for encrypt or dec for decrypt> \
		 <input file> <output file>\n", argv[0]);
		exit(EXIT_FAILURE);
	}
	
	//encrypt file
	if(strcmp(argv[1], "enc") == 0)
	{
		fIN = fopen(argv[2], "rb"); //File to be encrypted; plain text
		fOUT = fopen(argv[3], "wb"); //File to be written; cipher text

		crypt(TRUE, fIN, fOUT, ckey, ivec);

		fclose(fIN);
		fclose(fOUT);
	}
	//Decrypt file
	else if(strcmp(argv[1], "dec") == 0)
	{
		fIN = fopen(argv[2], "rb"); //File to be read; cipher text
		fOUT = fopen(argv[3], "wb"); //File to be written; cipher text

		crypt(FALSE, fIN, fOUT, ckey, ivec);

		fclose(fIN);
		fclose(fOUT);
	}
	else
	{
		printf("error input in argv[1].(should be \"enc\" or \"dec\")\n");
	}
	return 0;
}
