#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>

typedef struct {
	int sock;
	int addr_len;
	struct sockaddr_in ssh_addr;
	struct sockaddr address;
	const char *key;
} conn_th;

struct ctr_state {
	unsigned char ivec[AES_BLOCK_SIZE];  
	unsigned int num; 
	unsigned char ecount[AES_BLOCK_SIZE]; 
};

/*
struct hostent {
char*    h_name;       
char**   h_aliases;    
 int      h_addrtype;   ;; host address type 
int      h_length;     ;; length of address 
char**   h_addr_list;  ;; list of addresses 
}
*/

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

	int my_flag = connect(fd, (struct sockaddr *)&connected->ssh_addr, sizeof(connected->ssh_addr));

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


void main(int argc, char *argv[]) {
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
					fprintf(stderr, "Error:Port number missing in the arguments\n");
					return 0;
				} else if (optopt == 'k') {
					fprintf(stderr, "Error:No Key file in the argument\n");
					return 0;
				} else {
					fprintf(stderr, "Error: Absurd case\n");
					return 0;
				}
			default:
				fprintf(stderr, "Error: Wrong arguments\n");
				return 0;
		}
	}
	
	// get destination ip and port
	if (optind == argc - 2) {
		destn_host = argv[optind];
		dest_port = argv[optind+1];
	} 
	else {
		fprintf(stderr, "Error: %d, Args Count :/  %d\n", optind, argc);
		fprintf(stderr, "Error: Wrong destn host/ip and port\n");
		return 0;
	}
	
	if (InpKeyFile == NULL) {
		fprintf(stderr, "No Key?\n");
		return 0;
	}
	
	fprintf(stderr, "\n Execution starting with the PbProxy :\n server mode: %s\t listening port: %s\t key file: %s\t destination addr: %s\t destination port: %s\n", source_port, InpKeyFile,destn_host, dest_port);

	//Read the input Key File.
	const char * Key = read_file(InpKeyFile);
	if(!Key) {
		fprintf(stderr, "Error: Key Reading has failed!");
		return 0;
	}

	struct hostent *host_pack;

	/*

	#include <netdb.h>
	extern int h_errno;
	struct hostent *gethostbyname(const char *name);
	
	The gethostbyname() function returns a structure of type hostent for the given host name. Here name is either a hostname, or an IPv4 address in standard dot notation

	*/
	if((host_pack = gethostbyname(destn_host))==0){
		fprintf(stderr, "Error: Not able to find the host name(hostent)\n", );
		return 0;
	}


	//parse the input destn port & listen_port number.
	int dst_port = (int)strtol(dest_port, NULL, 10);
	//parse the listen port number
	int listen_port = (int)strtol(source_port, NULL, 10);

	struct sockaddr_in server_addr, ssh_addr;

	// Fill the first n bits of the addresses with 0's if there are any.

	bzero(&server_addr, sizeof(server_addr));
	//	bzero(&ssh_addr,sizeof(ssh_addr));	
	bzero(&server_addr,sizeof(ssh_addr));

	if(flag_server){
		conn_th *conncetion;
		pthread_t thread;
		int fd = socket(AF_INET, SOCK_STREAM,0);

		server_addr.sin_family = AF_INET;
		// converts the unsigned short integer hostshort from host byte order to network byte order
		server_addr.sin_addr.s_addr = htons(INADDR_ANY);
		server_addr.sin_port = htons(listen_port);

		ssh_addr.sin_family = AF_INET;
		ssh_addr.sin_port = htons(dst_port);
		ssh_addr.sin_addr.s_addr = ((struct in_addr *) (host_pack->h_addr))->s_addr;

		//binding the connection

		bind(fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
		if(listen(fd,10)<0){
			fprintf(stderr, "Error: Not able to listen :( \n");
			return 0;
		}

		while(1){
			connection = (conn_th *)malloc(sizeof(conn_th));
			connection->sock = accept(fd, &connection->address, &connection->addr_len);
			if(connection->sock > 0 ){
				connection->ssh_addr = ssh_addr;
				connection->key = Key;
				pthread_create(&thread, 0, server_process, (void)* connection);
				pthread_detach(thread);
			}
			else{
				free(conncetion);
			}
		  
		}
	}
	else{
		char buf[4096];
		int fd_client = socket(AF_INET, SOCK_STREAM, 0);

		server_addr.sin_family = AF_INET;
		server_addr.sin_port = htons(dst_port);
		ssh_addr.sin_addr.s_addr = ((struct in_addr *) (host_pack->h_addr))->s_addr;

		int cFlag = connect(fd_client, (struct sockaddr *)&server_addr, sizeof(server_addr));
		if (cFlag == -1) {
			fprintf(stderr, "Error: Connection Unsuccessful :( \n", );
			return 0;
		}

		fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);
		// set the status change flags - not similar to duplicating fds.
		fcntl(fd_client, F_SETFL, O_NONBLOCK);

		struct ctr_state state;
		unsigned char iv[8];
		AES_KEY aes_key;

		if (AES_set_encrypt_key(connected->key, 128, &aes_key) < 0){
			fprintf(stderr, "Error: Couldnt set encryption. \n");
			exit(1);
		}

		int check;
		while(1){
			while((check = read(STDIN_FILENO, buf, 4096))>=0){			
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
				write(fd_client, temp, check+8);
				free(temp);

				//absurd case
				if(check < 4096){
					break;
				}
			}

			while((check = read(fd_client, buf, 4096))>0){
				if (check < 8){
					fprintf(stderr, "Error:PLength smaller than 8 \n");
					//Close connection as socket open error occurred.
					close(fd_client);
					return 0;
				}
				//copy the IV in the buffer.
				memcpy(iv, buf, 8);

				//Calling the initialisation function to initialise the parameters to 0
				init_ctr(&state,iv);		
				unsigned char decryptV[check-8];
				AES_ctr128_encrypt(buf+8, decryptV, check-8, &aes_key, state.ivec, state.ecount, &state.num );
				// write the encrpyted contents to the file 
				write(STDIN_FILENO, decryptV, check-8 );
				//Error case, where check indicates the relay factor
				if (check < 4096 ){
					break;
				}
			}

		}

	}

}


