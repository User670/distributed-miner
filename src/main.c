#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sha2.h>
#include <time.h>
/*
hmm this sha256 function deals with strings? wonder if it can handle bytes
*/

/*
I'll eventually have to clea up my bull crap comments here

The chunk of data to be hashed will be in this format:
4 bytes, version number. We'll use 2.
32 bytes, hash from previous block. I wonder what the first block in the
  chain uses? All zeros?
32 bytes, hash from this block's transactions. We'll go RNG on it.
4 bytes, timestamp. Wait till 2038...
4 bytes, difficulty. We'll use 0x1e03a307
4 bytes, nonce.

Everything is in little endian, eg. version number will be
02 00 00 00, not 00 00 00 02, and the previous block hash will
have the chunks of zeros at the end.
*/

//the integer 2, in little endian
const char version_number[4]={0x02, 0x00, 0x00, 0x00};

/*====================================
  begin hash cracking code
  ====================================*/

//calculate double SHA256 of some data, and store it at specified buffer
void dsha(const unsigned char* message, unsigned int len, unsigned char* digest){
	sha256(message, len, digest);
	sha256(digest, 32, digest);
}

//compare the calculated hash with the target.
//target will be given in the extended form, not compact.
int miner_compare_hash(const void* str1, const void* str2){
	return memcmp(str1, str2, 32)<0;
}

//construct header.
//version number 2 is implied.
void miner_construct_header(
	const unsigned char* previous_block_hash,
	const unsigned char* merkle_root,
	time_t timestamp,
	const unsigned char* target,
	int nonce,
	const unsigned char* buffer
){
	printf("\nbegin miner_construct_header\n");
	memcpy(buffer, &version_number, 4);
	printf("\na\n");
	memcpy(buffer+4, previous_block_hash, 32);
	printf("\nb\n");
	memcpy(buffer+36, merkle_root, 32);
	int_to_little_endian_bytes(timestamp, buffer+68);
	memcpy(buffer+72, target, 4);
	int_to_little_endian_bytes(nonce, buffer+76);

	memrev(buffer+4, 32);
	memrev(buffer+36, 32);
	memrev(buffer+72, 4);
	printf("\nend miner_construct_header");
}

//https://github.com/troglobit/snippets/blob/master/memrev.c
//reverse a chunk of buffer.
void memrev(char *buf, size_t count){
    char *r;
	for (r = buf + count - 1; buf < r; buf++, r--){
	    *buf ^= *r;
	    *r   ^= *buf;
	    *buf ^= *r;
    }
}

//basically
//https://stackoverflow.com/questions/3784263/converting-an-int-into-a-4-byte-char-array-c
//convert an integer into a 4-byte little endian byte sequence.
void int_to_little_endian_bytes(int n, unsigned char* buffer){
	*buffer    = n     &0xFF;
	*(buffer+1)=(n>>8) &0xff;
	*(buffer+2)=(n>>16)&0xff;
	*(buffer+3)=(n>>24)&0xff;
}

void debug_print_hex(const unsigned char* buffer, int size){
	for(int i=0; i<size; i++){
		printf("%02X",*(buffer+i));
	}
	printf("\n");
}


int main(){
	//testing int to little endian bytes
	char* int2bytes[4];
	int_to_little_endian_bytes(2, int2bytes);
	debug_print_hex(int2bytes,4);

	//testing construct header
	printf("\n1");
	char hash1[]={
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
		0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
		0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
	};
	printf("\n2");
	char target[4]={0x81, 0x82, 0x83, 0x84};
	printf("\n3");
	char* header=malloc(80);
	printf("\n4");
	miner_construct_header(
		*hash1,
		*hash1,
		86400,
		*target,
		2147483647,
		header
	);
	debug_print_hex(header, 80);
}