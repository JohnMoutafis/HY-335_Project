#include <stdlib.h>
#include <stdio.h> 
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include "cloudbox.h"
#include <sys/time.h>
#include <time.h>
#include <stddef.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h> 
#include <arpa/inet.h>
//add a new include by rafas
#include <sys/stat.h>

/*
 * The list that holds all the current watched files.
 * 
 * It is very convinient this list to be shorted by the file name
 * in order to be able to find immediatly inconsistencies,
 */
struct dir_files_status_list *watched_files;
struct dir_files_status_list current_file; /*added by jagathan*/

/*
 * Print mutex, for printing nicely the messages from different threads
 */
pthread_mutex_t print_mutex;


/* 
 * Mutex used to protect the accesses from different threads
 * of the file list of the watched directory
 */
pthread_mutex_t file_list_mutex;

char *watched_dir; /*added by jagathan*/

/*insert from list*/
struct dir_files_status_list* insert_file(struct dir_files_status_list *head,char *filename ,size_t size_in_bytes ,char sha1sum[SHA1_BYTES_LEN],
                                        long long int modifictation_time_from_epoch){

        struct dir_files_status_list *cur ,*newnode,*prev;
        prev=NULL;
        cur=head;
        while((cur)&&(strcmp(filename,cur->filename)>0)){
                prev=cur;
                cur=cur->next;
        }
        if((cur)&&(strcmp(cur->filename,filename)==0))
                return head;

        newnode=(struct dir_files_status_list*)malloc(sizeof(struct dir_files_status_list));
        newnode->filename=(char*)malloc(sizeof(char*));
        strcpy(newnode->filename,filename);
        strcpy(newnode->sha1sum,sha1sum);
        newnode->size_in_bytes=size_in_bytes;
        newnode->modifictation_time_from_epoch=modifictation_time_from_epoch;
        newnode->next=cur;
        newnode->previous=prev;
        if((!cur)&&(!prev)){
                head=newnode;
                return head;
        }
        if(!cur){
                prev->next=newnode;
                return head;
        }
        if(!prev)
               head=newnode;
        else{
               prev->next=newnode;
               cur->previous=newnode;
        }
        return head;
}

/*delete from list*/
struct dir_files_status_list* delete_file(struct dir_files_status_list *head,char *filename){
			struct dir_files_status_list *cur,*prev,*next;
			cur=head;
	        prev=NULL;
	        while((cur)&&(strcmp(cur->filename,filename)!=0)){
	                prev=cur;
	                cur=cur->next;
	        }
	        if(!cur)
	                return head;
	        if(!prev){

	                prev=cur;
	                cur=cur->next;
	                if(cur)
	                	cur->previous=NULL;
	                free(prev->filename);
	                free(prev);
	                return cur;
	        }
	        if(!cur->next){
	                prev->next=NULL;
	                free(cur->filename);
	                free(cur);
	                return head;
	        }
	        prev->next=cur->next;
	        next=cur->next;
	        next->previous=prev;
	        free(cur->filename);
	        free(cur);
	        return head;
}

/*
 * Message functions
 * Moutafis
 */
full_msg full_message_creator(msg_type_t msg, char* client_name, int TCP_lp, int curr_ts, int file_mts, char* file_name,char* checksum, int file_lngh)
{
	full_msg ret;
	//default part of the message
	ret.msg_type = msg;
	ret.TCP_listening_port = TCP_lp;
	ret.current_time_stamp = curr_ts;
	int size_of_cname = strlen(client_name) + 2, i;
	char tmp_cname[size_of_cname];
	tmp_cname[0] = 0x0;
	for(i=1; i<=strlen(client_name); i++)
	{
		tmp_cname[i] = client_name[i-1];
	}
	tmp_cname[size_of_cname+1] = 0x0;
	ret.client_name = tmp_cname;
	//Non default cases:
	ret.file_mod_time_stamp = file_mts;
	ret.file_length = file_lngh;
	int size_of_fname = strlen(file_name) + 1;
	char tmp_fname[size_of_fname];
	tmp_fname[0] = 0x0;
	for(i=1; i<=size_of_fname; i++)
	{
		tmp_fname[i] = file_name[i-1];
	}
	tmp_fname[size_of_fname] = 0x0;
	ret.file_name = tmp_fname;
	ret.sha1_checksum = checksum;
	return ret;
}

void message_interpretation(full_msg incoming)
{
	int i;
	int cname_size = sizeof(incoming.client_name), fname_size = sizeof(incoming.file_name);
	char cname_tmp[cname_size], fname_tmp[fname_size];
	for(i=1; i<cname_size-1; i++)
	{
		cname_tmp[i-1] = incoming.client_name[i];
	}
	for(i=1; i<fname_size-1; i++)
	{
		fname_tmp[i-1] = incoming.file_name[i];
	}
	//Message Cases
	if (incoming.msg_type == STATUS_MSG)
	{
		printf("STATUS_MSG\n0x1 ");
		printf(" %s",cname_tmp);
		printf(" %d",incoming.TCP_listening_port);
		printf(" %ld\n",incoming.current_time_stamp);
	}
	else if(incoming.msg_type == NO_CHANGES_MSG)
	{
		printf("NO_CHANGES_MSG\n0x2");
		printf(" %s",cname_tmp);
		printf(" %d",incoming.TCP_listening_port);
		printf(" %ld",incoming.current_time_stamp);
		printf(" %s\n",incoming.sha1_checksum);
	}
	else if(incoming.msg_type == NEW_FILE_MSG)
	{
		printf("NEW_FILE_MSG\n0x3");
		printf(" %s",cname_tmp);
		printf(" %d",incoming.TCP_listening_port);
		printf(" %ld ",incoming.current_time_stamp);
		printf(" %s",fname_tmp);
		printf(" %ld\n",incoming.file_length);
	}
	else if(incoming.msg_type == FILE_CHANGED_MSG)
	{
		printf("FILE_CHANGED_MSG\n0x4");
		printf(" %s",cname_tmp);
		printf(" %d",incoming.TCP_listening_port);
		printf(" %ld ",incoming.current_time_stamp);
		printf(" %s",fname_tmp);
		printf(" %ld\n",incoming.file_mod_time_stamp);
	}
	else if(incoming.msg_type == FILE_DELETED_MSG)
	{
		printf("FILE_DELETED_MSG\n0x5");
		printf(" %s",cname_tmp);
		printf(" %d",incoming.TCP_listening_port);
		printf(" %ld ",incoming.current_time_stamp);
		printf(" %s",fname_tmp);
		printf(" %ld",incoming.file_mod_time_stamp);
		printf(" %ld\n",incoming.file_length);
	}
	else if(incoming.msg_type == FILE_TRANSFER_REQUEST)
	{
		printf("FILE_TRANSFER_REQUEST\n0x6");
		printf(" %s",cname_tmp);
		printf(" %d",incoming.TCP_listening_port);
		printf(" %ld ",incoming.current_time_stamp);
		printf(" %s\n",fname_tmp);
	}
	else if(incoming.msg_type == FILE_TRANSFER_OFFER)
	{
		printf("FILE_TRANSFER_OFFER\n0x7");
		printf(" %s",cname_tmp);
		printf(" %d",incoming.TCP_listening_port);
		printf(" %ld ",incoming.current_time_stamp);
		printf(" %s",fname_tmp);
		printf(" %ld\n",incoming.file_length);
	}
	else if(incoming.msg_type == DIR_EMPTY)
	{
		printf("DIR_EMPTY\n0x8");
		printf(" %s",cname_tmp);
		printf(" %d",incoming.TCP_listening_port);
		printf(" %ld ",incoming.current_time_stamp);
		printf(" %s\n",incoming.sha1_checksum);
	}
}
/*END OF MESSAGE FUNCTIONS*/

/**Function of TCP Client*/
void tcp_client(){
  
  int sock;
  
 // struct sockaddr *client_addr;
 // socklen_t client_addr_len;

  if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
    perror("opening TCP socket");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in sin;
  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  /*Port that server listens at */
  sin.sin_port = htons(6886);
  /* The server's IP*/
  sin.sin_addr.s_addr = inet_addr("192.168.1.212");

  if(connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1){
    perror("tcp connect");
    exit(EXIT_FAILURE);
  }
  sleep(15);
  send(sock, "Hello Server!", 14, 0);
  close(sock);
  
}


/*Function of UDP Client that connects to udp thread server*/
/*jagathan*/
void* udp_client(void* param){
	int sock;
	int* port=(int*)param;
	unsigned int i = 0;
	 
	/* UNUSED VARS
	struct sockaddr *client_addr;
	socklen_t client_addr_len;*/ 
	if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
	    	perror("opening UDP socket");
	    	exit(EXIT_FAILURE);
	}
	int broadcastEnable=1;
	int ret=setsockopt(sock, SOL_SOCKET, SO_BROADCAST, &broadcastEnable, sizeof(broadcastEnable));
	if (ret) {
	    	perror("Error: Could not open set socket to broadcast mode");
		close(sock);
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	/*Port that server listens at */
	sin.sin_port = htons(*port);
	/* The broadcast IP*/
	sin.sin_addr.s_addr = inet_addr("255.255.255.255");
	while(i < 10){
		printf("Look me, look me I do not block !!! \n");
	    	if( sendto(sock,"Hello Server!",14, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
			perror("send status report");
			exit(EXIT_FAILURE);
		}
		i++;
		sleep(1);
	}
	close(sock);
}

/**Function of TCP Server*/
void tcp_server(){
  char buffer[512];
  
  int sock;
  int accepted;
  int received;
  
  struct sockaddr_in sin;

  struct sockaddr client_addr;
  socklen_t client_addr_len;

  
  if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
    perror("opening TCP socket");
    exit(EXIT_FAILURE);
  }
  
  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(6886);
  /* Bind to all available network interfaces */
  sin.sin_addr.s_addr = INADDR_ANY;

  if(bind(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1){
    perror("TCP bind");
    exit(EXIT_FAILURE);
  }

  if(listen(sock, 1000) == -1){
    perror("TCP listen");
    exit(EXIT_FAILURE);
  }

  /* Ok, a tricky part here. See man accept() for details */

  client_addr_len = sizeof(struct sockaddr);
  while((accepted = accept(sock, &client_addr, &client_addr_len)) > 0 ){
    printf("New connection accepted!\n");
    received = recv(accepted, buffer, 511, 0);
    buffer[received] = 0;
    printf("Received from client: %s\n",buffer);
    close(accepted);
  }
}

/*Function of UDP Server usinig threads*/
/*jagathan*/
void* udp_server(void* param){
	char buffer[512];  
	int sock;
	/*int accepted;*/
	int received;
	
	int* port=(int*)param;
	struct sockaddr_in sin;

	/* UNUSED VARS
	struct sockaddr client_addr;*/
	/*socklen_t client_addr_len;*/
	struct received_data *d;
	
	/*create socket*/
	if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
	    	perror("opening UDP soc	ket");
		exit(EXIT_FAILURE);
	}
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(*port);
	/* Bind to all available network interfaces */
	sin.sin_addr.s_addr = INADDR_ANY;
	
	/*create the new thread */
	pthread_t new_thread;// = malloc(sizeof(pthread_t));
 	pthread_attr_t thread_attributes;
	/* Initialize the attributes of the threads */
	pthread_attr_init(&thread_attributes);
	/*Set the detache state to JOINABLE*/
	pthread_attr_setdetachstate(&thread_attributes, PTHREAD_CREATE_JOINABLE);
	if(bind(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1){
	    	perror("UDP bind");
	    	exit(EXIT_FAILURE);
	}
	
	while(1){
	    	memset(buffer, 0, 512);
		if((received = read(sock, buffer, 511)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}	
		else{/*when recieves from a client opens a thread and do stuff*/	
			new_thread = malloc(sizeof(pthread_t));
			/*Create the thread and pass the socket discriptor*/
			buffer[received] = 0;
			d=(struct received_data*)malloc(sizeof(struct received_data));	
			d->data=(char*)malloc(sizeof(char*));
			strcpy(d->data,buffer);
			if(pthread_create(&new_thread, (void*)&thread_attributes,(void*) &udp_receiver_dispatcher_thread,(void*)d)!= 0){
			      perror("create thread");
			      exit(EXIT_FAILURE);
			}
	        } 
	}
	pause();
}
  
/*jagathan*/
/*handles every client that connects*/
void* udp_receiver_dispatcher_thread(void *params){
	struct received_data* msg=(struct received_data*)params;	
	printf("Received: %s\n",msg->data);
	printf("Going to sleep for 2 secs... Like a boss!\n");
	sleep(2);
	pthread_exit(NULL);
}
/*jagathan*/
/*computes sha1 an stores it in current_file struct*/
void compute_sha1_of_file(char *outbuff, char *filename){
	size_t length=strlen(filename);
	unsigned char hash[SHA1_BYTES_LEN];
	int i;	
	outbuff=SHA1(filename,length,hash);
	for(i=0;i<SHA1_BYTES_LEN;i++){
		current_file.sha1sum[i]=hash[i];
	}

}
/*Edit by Rafas*/
/**Function to find filesize portable*/
long filesize(const char *filename)
{
FILE *f = fopen(filename,"rb");  /* open the file in read only */

long size = 0;
  if (fseek(f,0,SEEK_END)==0) /* seek was successful */
      size = ftell(f);
  fclose(f);
  return size;
}
/*End of Changes*/


/*Get last Modified time from file
 By Rafas*/

long int *get_last_modified(char *file) {
    struct tm *clock,*clock1;
    struct stat attr;

    stat(file, &attr);
    clock = gmtime(&(attr.st_mtime));

    clock1 = mktime(clock);
    printf("\nHumans Time:%s", asctime(clock));
    return mktime(clock);
}

/*end rafas function*/

int main(int argc, char **argv){

	int opt;
	int scan_interval;
	int broadcast_port;
	int fsize=15;
	/*added now*/char p[100];
	char *client_name;
	char *watched_dir;
	DIR *dir;
        struct dirent *files;
	
	/*edited by jagathan*/
	pthread_t thread_udpserver;
  	pthread_t thread_udpclient;  
  	pthread_attr_t thread_udpserver_attributes;
  	pthread_attr_t thread_udpclient_attributes;
	/*end -jagathan*/
	
	/*added by rafas*/long long int clock;
	
	watched_files=NULL;
	
	/*
	 * Initialize the mutexes
	 */
	pthread_mutex_init(&print_mutex, NULL);
	pthread_mutex_init(&file_list_mutex, NULL);
	
	while ((opt = getopt(argc, argv, "hn:d:i:b:")) != -1) {
		switch(opt){
			case 'n':
				client_name = strdup(optarg);
				break;
				
			case 'd':
				watched_dir = strdup(optarg);
				/* A few checks will be nice here...*/
				/* Convert the given dir to absolute path */
				break;
			case 'i':
				scan_interval = atoi(optarg);
				break;
			case 'b':
				broadcast_port = atoi(optarg);
				/* To check or not to check? */
				break;
			default:
				printf("Usage: cloudbox -n client_name -d directory_to_use -i scan_interval -b broadcast_port\n"
				"Options:\n"
				"   -n                  Specifies the name of the client\n"
				"   -d                  The directory absolute path, to watch for changes\n"
				"   -i                  The interval time in seconds, that the client should scan for file changes\n"
				"   -b                  The port that is going to be used for receiving and transmitting broadcasts UDP meesages\n"
				"   -h                  prints this help\n");
				exit(EXIT_FAILURE);
		}
	}
	
	printf("Cloudbox client %s:\n"
		   "Wathced directory: %s\n"
		   "Scan interval: %d seconds\n"
		   "Broadcast port: %d\n",
		client_name, watched_dir, scan_interval, broadcast_port);

	/*AREA 51 TEST AREA!! PLEASE REMOVE "YOU DIDN'T SEE ANYTHING"*/
	full_msg full_test = full_message_creator(NEW_FILE_MSG, client_name, broadcast_port, 1548784512, 1548784512, watched_dir,"abcdefgghshjjdaaseee", 100);
	message_interpretation(full_test);
	/*AREA 51 TEST AREA!! PLEASE REMOVE "YOU DIDN'T SEE ANYTHING"*/

	dir=opendir(watched_dir);/*opens directory watched_dir and copies files in watched_files list*/
	/*added now*/strcat(watched_dir,"/");
	if(!dir){
		printf("\nThe directory path does not exist ");
		exit(-1);
	}
        files=readdir( dir);
        while(files){
                 /*Edit by Rafas*/
		
		strcpy(p,watched_dir);
		
		
		strcat(p,files->d_name);
		printf("File:  %s",files->d_name);
		clock=get_last_modified(p);
		printf("Since the Epoch: [%ld seconds]\n",clock);
		fsize=filesize(p);
		compute_sha1_of_file(files->d_name,current_file.sha1sum);/* added by jagathan */
		printf("File size: %d bytes\n\n", fsize);
		
                watched_files=insert_file(watched_files,files->d_name,fsize,current_file.sha1sum,clock);
                files=readdir(dir);
                
                
                
		/*End of Changes*/
        }
        while(watched_files){/*prints watched_files list*/
                printf("\n%s",watched_files->filename);
                watched_files=watched_files->next;
        }
	
	/* Edited by jagathan */
	/*create the threads for udp server and client*/
	/* Initialize the attributes of the threads */
	pthread_attr_init(&thread_udpserver_attributes);
	pthread_attr_init(&thread_udpclient_attributes);
	/*Set the detache state to JOINABLE*/
	pthread_attr_setdetachstate(&thread_udpserver_attributes, PTHREAD_CREATE_JOINABLE);
	pthread_attr_setdetachstate(&thread_udpclient_attributes, PTHREAD_CREATE_JOINABLE);
	
	if( pthread_create(&thread_udpserver, &thread_udpserver_attributes, &udp_server,(void*)&broadcast_port) != 0){
		perror("create thread udpserver");
	    	exit(EXIT_FAILURE);
  	}	
	if( pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,(void*)&broadcast_port) != 0){
		perror("create thread udpclient");
	    	exit(EXIT_FAILURE);
  	}
	
	pause();	
	/* end -jagathan*/
	return 0;
}
