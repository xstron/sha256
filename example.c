#include "libsha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print_hash(uint32_t *buffer)
{
	for (int i = 0; i < 8; i++) {
		printf("%08x", buffer[i]);
	}
	printf("\n");
}

int main(void)
{
	void *hash_buffer = malloc(SHA256_HASH_SIZE);

	void *message = malloc(1337);
	memset(message, 'Q', 1337);

	sha256(message, 1337, hash_buffer);

	/* 83d3a2306c1ad9f595a92bec56d7fd3acf9501f9898ccfefe7f3e5351b3f42af */
	print_hash(hash_buffer);

	free(message);
	free(hash_buffer);

	return 0;
}