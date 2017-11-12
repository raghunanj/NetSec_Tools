#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include<openssl/aes.h>

typedef struct {
	int sock;
	int addr_len;
	struct sockaddr_in sshaddr;
	struct sockaddr address;
	const char *key;
} conn_th;

struct ctr_state {
	unsigned char ivec[AES_BLOCK_SIZE];  
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
};

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

// Function to initialise the encryption vectors to zero before the main execution.
int init_ctr(struct ctr_state *state, const unsigned char iv[8]) {
	state->num = 0;
	memset(state->ecount, 0, AES_BLOCK_SIZE);
	memset(state->ivec + 8, 0, 8);
	memcpy(state->ivec, iv, 8);
}

void* server_process(void* th_p) {
	//Exit case if the thread is not created.
	if(!th_pointer) { 
		pthread_exit(0);
	}
	//printf("Thread starts here");

	conn_th* connected = (conn_th *)th_p;
	char buf[4096];
	int fd;
	int ssh_flag = 0;

	//Opening a socket connection
	fd = socket(AF_INET, SOCK_STREAM, 0);

	int my_flag = connect(fd, (struct sockaddr *)&connected->sshaddr, sizeof(connected->sshaddr));

	//Server socket conncetion status check
	if (my_flag == -1) {
		printf("Conncetion Unsuccessful :/ \n");
		//Exit the thread.
		pthread_exit(0);
	}
	else{
		printf("Connection successful");
	}

	int dup_flag = fcntl(connection->sock, F_GETFL);

	if (dup_flag == -1) {
		printf( " First socket connection error ");
		//Close connection as socket open error occurred.
		close(connected->sock);
		close(fd);
		//Exit the thread.
		pthread_exit(0);
	}
	fcntl(connected->sock, F_SETFL, flags | O_NONBLOCK);

	// GEt the File status flags
	if(fcntl(fd, F_GETFL) == -1){
		printf("Error : Could not open the file ");
		pthread_exit(0);
	}
	// SET the status as non blocking
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);

	struct ctr_state state;
	AES_KEY aes_Key;
	unsigned char iv[8];

	if (AES_set_encrypt_key(connected->key, 128, &aes_key) < 0){
		fprintf(stderr, "Error: Couldnt set encryption. \n");
		exit(1);
	}

	// Listening connection
	int check;
	while(1){
		while((check = read(connected->sock, buf, 4096))>0){
			if (check < 8){
				printf("Error:PLength smaller than 8 \n");
				//Close connection as socket open error occurred.
				close(connected->sock);
				close(fd);
				//Exit the thread.
				pthread_exit(0);
			}
			//copy the IV in the buffer.
			memcpy(iv, buf, 8);

			//Calling the initialisation function to initialise the parameters to 0
			init_ctr(&state,iv);		
			unsigned char decryptV[check-8];
			AES_ctr128_encrypt(buf+8, decryptV, check-8, &aes_key, state.ivec, state.ecount, &state.num );
			write(fd, )

		}
	}
}


int main(int argc, char *argv[]) {

	// Some code for listening and parsing the input arguments

}


