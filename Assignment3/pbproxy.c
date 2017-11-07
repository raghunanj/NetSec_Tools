#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>


char* read_file(char* filename){
	char* buf = 0;
	unsigned long len;
	FILE *fd = fopen(filename, "rb");

	if (fd){
		fseek(fd, 0 , SEEK_END);
		len = ftell(fd);
		fseek(fd, 0, SEEK_SET);
		buf = malloc(len);
		if(buf){
			fread(buf, 1, len,fd);
		fclose(fd);
		} 
	}
	else 
		return 0;

	return buf;
}

int main(int argc, char *argv[]) {
}


