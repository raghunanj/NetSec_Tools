#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>

#include <openssl/aes.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

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
			// write the encrpyted contents to the file 
			write(fd, decryptV, check-8 );
			//Error case, where check indicates the relay factor
			if (check < 4096 ){
				break;
			}
		}

		//When server is actually sending the info
		while((check = read(fd, buf, 4096))>=0){
			if(check > 0){
				if(!RAND_bytes(iv, 8)) {
					fprintf(stderr, "Error: generating random bytes \n", );
					exit(1);
				}
				// incrementing the IV by 8, adjustment factor
				char* temp = (char*)malloc(check+8);
				memcpy(temp,iv,8);

				init_ctr(&state, iv);
				unsigned char encryptV[check];
				AES_ctr128_encrypt(buf, encryptV, check, &aes_key, state.ivec, state.ecount, &state.num);
				memcpy(temp+8, encryptV, check);
				//Relaying/writing the info on the socket
				write(connected->sock, temp, check+8);
			}

			//If all the info has been sent exit from the loop or connection
			if (ssh_flag == 0 && check == 0){
				ssh_flag = 1;
			}

			//absurd case
			if(check < 4096){
				break;
			}
		}

		if(ssh_flag){
			break;
		}

	}

	//Failure to establish a connection
	printf("Error: No connection established ");
	//Close connection as socket open error occurred.
	close(connected->sock);
	close(fd);
	//Exit the thread.
	pthread_exit(0);
}


int main(int argc, char *argv[]) {
	int inputOptions = 0;
	int flag_server = 0;
	char *InpKeyFile = NULL;
	char *source_port = NULL;
	char *destn_host = NULL;
	char *dest_port = NULL;

	
	while ((inputOptions = getopt(argc, argv, "l:k")) != -1) {
		switch(inputOptions) {
			case 'l':
				source_port = optarg;
				flag_server = 1;
				break;
			case 'k':
				InpKeyFile = optarg;
				break;
			case '?':
				if (optopt == 'l') {
					fprintf(stderr, "Port number missing in the arguments\n");
					return 0;
				} else if (optopt == 'k') {
					fprintf(stderr, "No Key file in the argument\n");
					return 0;
				} else {
					fprintf(stderr, "Absurd case\n");
					return 0;
				}
			default:
				fprintf(stderr, "Wrong arguments\n");
				return 0;
		}
	}
	
	// get destination ip and port
	if (optind == argc - 2) {
		destn_host = argv[optind];
		dest_port = argv[optind+1];
	} else {
		fprintf(stderr, "optind: %d, argc: %d\n", optind, argc);
		fprintf(stderr, "Incorrect destination and port arguments. Exiting...\n");
		return 0;
	}
	
	if (InpKeyFile == NULL) {
		fprintf(stderr, "Key file not specified!\n");
		return 0;
	}
	
	fprintf(stderr, "\n Execution starting with the PbProxy :\n server mode: %s\t listening port: %s\t key file: %s\t destination addr: %s\t destination port: %s\n", source_port, InpKeyFile,destn_host, dest_port);


}


