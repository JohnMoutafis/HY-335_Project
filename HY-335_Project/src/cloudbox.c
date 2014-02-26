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
#include <math.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <sys/file.h>
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
pthread_mutex_t tcp_client_mutex;
char *watched_dir; /*added by jagathan*/
char* client_ip;
int tcp_flag=0;
int broadcast_messages;
long incoming_kbs;
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

/**
 * AUXILIARY
 */
void eight_byte_mod(unsigned char mod_array[], int timestamp){
	mod_array[0] = (timestamp & 0xff00000000000000) >> 56;
	mod_array[1] = (timestamp & 0x00ff000000000000) >> 48;
	mod_array[2] = (timestamp & 0x0000ff0000000000) >> 40;
	mod_array[3] = (timestamp & 0x000000ff00000000) >> 32;
	mod_array[4] = (timestamp & 0x00000000ff000000) >> 24;
	mod_array[5] = (timestamp & 0x0000000000ff0000) >> 16;
	mod_array[6] = (timestamp & 0x000000000000ff00) >>  8;
	mod_array[7] =  timestamp & 0x00000000000000ff       ;
}

/**
 * Message to bytes creator
 */
void message_creator(unsigned char* full_message_buffer, msg_type_t msg, char* client_name,int TCP_lp, int curr_time, int file_mts, int file_lngh, char* file_name, char* checksum, int ok){
	//Default part of the message
	int i, n, default_buffer_size = 12+ strlen(client_name);
	unsigned char eight_byte[8];
    full_message_buffer = (unsigned char*)realloc(full_message_buffer, default_buffer_size*sizeof(unsigned char));
	//Type
	full_message_buffer[0] = msg & 0xff00;
	full_message_buffer[1] = msg & 0x00ff;
	full_message_buffer[2] = 0x0;
	//Name between 0x0
	for(i=0;client_name[i]!='\0';i++){
		full_message_buffer[3+i] = client_name[i];
	}
	full_message_buffer[3+i] = 0x0;
	i=i+4;
	//Tcp listening port
	full_message_buffer[i] = (TCP_lp >> 8) & 0xff;
	i++;
	full_message_buffer[i] = TCP_lp & 0xff;
	i++;
	// Current timestamp
	eight_byte_mod(eight_byte, curr_time);
	for(n=0; n<8; n++){
		full_message_buffer[i+n] = eight_byte[n];
	}
	i+=n;
	//All the message cases:
	if (msg == NO_CHANGES_MSG){
		int buffer_size = default_buffer_size + 22;
		full_message_buffer = (unsigned char*)realloc(full_message_buffer, buffer_size*sizeof(unsigned char));
		//Checksum
		for(n=0; checksum[n]!= '\0'; n++){
			full_message_buffer[i+n] = checksum[n];
		}
	}
	else if (msg == NEW_FILE_MSG){
		int buffer_size = default_buffer_size + strlen(file_name)+10;
		full_message_buffer = (unsigned char*)realloc(full_message_buffer, buffer_size*sizeof(unsigned char));
		//filename between 0x0
		full_message_buffer[i] = 0x0;
		i++;

		for(n=0; file_name[n]!='\0'; n++){

			full_message_buffer[i+n] = file_name[n];

		}
		i+=n;
		//file length
		eight_byte_mod(eight_byte, file_lngh);
		for(n=0; n<8; n++){

			full_message_buffer[i+n] = eight_byte[n];
		}
	}
	else if(msg==FILE_CHANGED_MSG){
		int buffer_size = default_buffer_size + strlen(file_name)+18;
		full_message_buffer = (unsigned char*)realloc(full_message_buffer, buffer_size*sizeof(unsigned char));
		//filename between 0x0
		full_message_buffer[i] = 0x0;
		i++;

		for(n=0; file_name[n]!='\0'; n++){

			full_message_buffer[i+n] = file_name[n];

		}
		i+=n;
		//file length
		eight_byte_mod(eight_byte, file_lngh);
		for(n=0; n<8; n++){

			full_message_buffer[i+n] = eight_byte[n];
		}
		i+=n;
		//file modification timestamp
		eight_byte_mod(eight_byte, file_mts);
		for(n=0; n<8; n++){

			full_message_buffer[i+n] = eight_byte[n];
		}
	}
	else if(msg==FILE_DELETED_MSG){
		int buffer_size = default_buffer_size + strlen(file_name)+18;
		full_message_buffer = (unsigned char*)realloc(full_message_buffer, buffer_size*sizeof(unsigned char));
		//filename between 0x0
		full_message_buffer[i] = 0x0;
		i++;

		for(n=0; file_name[n]!='\0'; n++){

			full_message_buffer[i+n] = file_name[n];

		}
		i+=n;
		//file length
		eight_byte_mod(eight_byte, file_lngh);
		for(n=0; n<8; n++){

			full_message_buffer[i+n] = eight_byte[n];
		}
		i+=n;
		//file modification timestamp
		eight_byte_mod(eight_byte, file_mts);
		for(n=0; n<8; n++){

			full_message_buffer[i+n] = eight_byte[n];
		}
	}
	else if(msg==FILE_TRANSFER_REQUEST){
		int buffer_size = default_buffer_size + strlen(file_name)+11;
		full_message_buffer = (unsigned char*)realloc(full_message_buffer, buffer_size*sizeof(unsigned char));
		//filename between 0x0
		full_message_buffer[i] = 0x0;
		i++;

		for(n=0; file_name[n]!='\0'; n++){

			full_message_buffer[i+n] = file_name[n];

		}
		i+=n;
		//file length
		eight_byte_mod(eight_byte, file_lngh);
		for(n=0; n<8; n++){

			full_message_buffer[i+n] = eight_byte[n];
		}
		i+=n;
		full_message_buffer[i] = ok & 0xff;
	}
	else if(msg==FILE_TRANSFER_OFFER){
		int buffer_size = default_buffer_size + strlen(file_name)+10;
		full_message_buffer = (unsigned char*)realloc(full_message_buffer, buffer_size*sizeof(unsigned char));
		//filename between 0x0
		full_message_buffer[i] = 0x0;
		i++;

		for(n=0; file_name[n]!='\0'; n++){

			full_message_buffer[i+n] = file_name[n];

		}
		i+=n;
		//file length
		eight_byte_mod(eight_byte, file_lngh);
		for(n=0; n<8; n++){

			full_message_buffer[i+n] = eight_byte[n];
		}
		i+=n;
		full_message_buffer[i] = ok & 0xff;
	}
	else if(msg==DIR_EMPTY){
		int buffer_size = default_buffer_size + 22;
		full_message_buffer = (unsigned char*)realloc(full_message_buffer, buffer_size*sizeof(unsigned char));
		//Checksum
		for(n=0; checksum[n]!= '\0'; n++){
			full_message_buffer[i+n] = checksum[n];
		}
	}
}

/**
 * Message reader
 */
full_msg read_message(unsigned char incoming[]){

	full_msg ret;
	int shift_8 = 56;
	int i, n=1;
	char c=incoming[3];
	//default message reader
	//msg type
	ret.msg_type = incoming[1];

	//client name
	while (c != 0x0){
		c = incoming[3+n];
		n++;
	}

	ret.client_name = (char*)malloc(n);

	for(i=0; i<n; i++){
		ret.client_name[i] = incoming[3+i];
	}
	i =i+3;

	//TCP listening port
	ret.TCP_listening_port = incoming[i] << 8;
	i++;
	ret.TCP_listening_port = ret.TCP_listening_port + incoming[i];
	i++;

	//Current timestamp
	for (n=0; n<8; n++){
		ret.current_time_stamp += (incoming[i+n] << shift_8);
		shift_8-=8;
	}
	i+=n;

	//Non default cases
	if(incoming[1] == NO_CHANGES_MSG){
		//checksum
		for (n=0; n<20; n++){
			ret.sha1_checksum[n] = incoming[i+n];
		}
		return ret;
	}
	else if(incoming[1] == NEW_FILE_MSG){
		i++;
		//file name
		c=incoming[i];
		int j=1;
		int x=0;
		while (incoming[i+x] != '\0'){
			c = incoming[i+n];
			j++;
			x++;
		}

		ret.file_name = (char*)malloc(j);
		for(n=0; n<x; n++){
			ret.file_name[n] = incoming[i+n];

		}
		i+=n;

		//file length
		for (n=0; n<8; n++){
			ret.file_length += (incoming[i+n] << shift_8);
			shift_8-=8;
		}
		i+=n;
		return ret;
	}
	else if(incoming[1]==FILE_DELETED_MSG){
		i++;
		//file name
		c=incoming[i];
		int j=1;
		int x=0;
		while (incoming[i+x] != '\0'){
			c = incoming[i+n];
			j++;
			x++;
		}

		ret.file_name = (char*)malloc(j);
		for(n=0; n<x; n++){
			ret.file_name[n] = incoming[i+n];

		}
		i+=n;

		//file length
		for (n=0; n<8; n++){
			ret.file_length += (incoming[i+n] << shift_8);
			shift_8-=8;
		}
		i+=n;
		shift_8 = 56;
		//file modification stamp
		for (n=0; n<8; n++){
			ret.file_mod_time_stamp += (incoming[i] << shift_8);
			shift_8-=8;
		}
		return ret;
	}
	else if(incoming[1]==FILE_CHANGED_MSG){
		i++;
		//file name
		c=incoming[i];
		int j=1;
		int x=0;
		while (incoming[i+x] != '\0'){
			c = incoming[i+n];
			j++;
			x++;
		}

		ret.file_name = (char*)malloc(j);
		for(n=0; n<x; n++){
			ret.file_name[n] = incoming[i+n];
		}
		i+=n;

		//file length
		for (n=0; n<8; n++){
			ret.file_length += (incoming[i+n] << shift_8);
			shift_8-=8;
		}
		i+=n;
		shift_8 = 56;
		//file modification stamp
		for (n=0; n<8; n++){
			ret.file_mod_time_stamp += (incoming[i] << shift_8);
			shift_8-=8;
		}
		return ret;
	}
	else if(incoming[1]==FILE_TRANSFER_REQUEST){
		i++;
		//file name
		c=incoming[i];
		int j=1;
		int x=0;
		while (incoming[i+x] != '\0'){
			c = incoming[i+n];
			j++;
			x++;
		}

		ret.file_name = (char*)malloc(j);
		for(n=0; n<x; n++){
			ret.file_name[n] = incoming[i+n];

		}
		i+=n;

		//file length
		for (n=0; n<8; n++){
			ret.file_length += (incoming[i+n] << shift_8);
			shift_8-=8;
		}
		i+=n;
		ret.ok = incoming[i];
		return ret;
	}
	else if(incoming[1]==FILE_TRANSFER_OFFER){
		i++;
		//file name
		c=incoming[i];
		int j=1;
		int x=0;
		while (incoming[i+x] != '\0'){
			c = incoming[i+n];
			j++;
			x++;
		}

		ret.file_name = (char*)malloc(j);
		for(n=0; n<x; n++){
			ret.file_name[n] = incoming[i+n];

		}
		i+=n;

		//file length
		for (n=0; n<8; n++){
			ret.file_length += (incoming[i+n] << shift_8);
			shift_8-=8;
		}
		i+=n;
		ret.ok = incoming[i];
		return ret;
	}
	else if(incoming[1]==DIR_EMPTY){

		for (n=0; n<20; n++){
			ret.sha1_checksum[n] = incoming[i+n];
		}
		return ret;
	}
	else{
		return ret;
	}
}
/*END OF MESSAGE FUNCTIONS*/

/**Function of TCP Client*/
void* tcp_client(void *params){
  	char c;
  	pthread_mutex_lock(&tcp_client_mutex);
	int sock;
	FILE *fd;
 	full_msg new_msg=*(full_msg*)params;

	if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
		perror("opening TCP socket");
		exit(EXIT_FAILURE);
	}
	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	/*Port that server listens at */
	sin.sin_port = htons(new_msg.TCP_listening_port);
	/* The server's IP*/
	sin.sin_addr.s_addr = inet_addr(client_ip);
	printf("\nTCPCLIENTT %d %s\n",new_msg.msg_type,client_ip);
	if(connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1){
		perror("tcp connect");
		exit(EXIT_FAILURE);
	}
	if(new_msg.msg_type==FILE_TRANSFER_REQUEST){
		send(sock, &new_msg, sizeof(new_msg),0);
		fd=fopen(strcat(watched_dir,new_msg.file_name),"w");
		while(read(sock,&c,1))
    	{
        		putc(c,fd);
        		printf("%c",c);
    	}

    	fclose(fd);
	}
	//incoming_kbs+=filesize(strcat(watched_dir,new_msg.file_name));
	if(new_msg.msg_type==FILE_TRANSFER_OFFER){
		send(sock, &new_msg, sizeof(new_msg),0);					
	}
	close(sock);
	pthread_mutex_unlock(&tcp_client_mutex);
	pthread_exit(NULL);
}
/*helper function to get the number of short int digits*/
int get_shortint_len (short int value){
	int l=2;
	while(value>9){ l++; value/=10; }
	return l;
}
/*helper function to get the number of long int digits*/
int get_longint_len (long int value){
	int l=2;
	while(value>9){ l++; value/=10; }
	return l;
}
/*Function of UDP Client that connects to udp thread server*/
/*jagathan*/
void* udp_client(void* param){
	//pthread_mutex_unlock(&print_mutex);
	int sock;
	full_msg new_msg=*(full_msg*)param;
	int port=new_msg.TCP_listening_port;
	
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
	sin.sin_port = htons(port);
	/* The broadcast IP*/
	sin.sin_addr.s_addr = inet_addr("255.255.255.255");
	
	print_string(new_msg.client_name);
	if(sendto(sock,&new_msg,sizeof(new_msg),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report1");
		exit(EXIT_FAILURE);
	}
	/*snprintf(str,get_shortint_len(new_msg.msg_type),"%hd",new_msg.msg_type);
	//printf("\n%s prwto send \n",str); 
	if(sendto(sock,str,strlen(str),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report1");
		exit(EXIT_FAILURE);
	}
	//message_interpretation(new_msg);
	
	if(sendto(sock,new_msg.client_name,strlen(new_msg.client_name),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report2");
		exit(EXIT_FAILURE);
	}
		
	snprintf(str,get_shortint_len(new_msg.TCP_listening_port),"%hd",new_msg.TCP_listening_port);
	if(sendto(sock,str,strlen(str),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report3");
		exit(EXIT_FAILURE);
	}
	
	snprintf(str,get_longint_len(new_msg.current_time_stamp),"%ld",new_msg.current_time_stamp);
	if(sendto(sock,str,strlen(str),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report4");
		exit(EXIT_FAILURE);
	}

	snprintf(str,get_longint_len(new_msg.file_mod_time_stamp),"%ld",new_msg.file_mod_time_stamp);
	if(sendto(sock,str,strlen(str),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report5");
		exit(EXIT_FAILURE);
	}

	if(sendto(sock,new_msg.file_name,strlen(new_msg.file_name),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report6");
		exit(EXIT_FAILURE);
	}

	if(sendto(sock,new_msg.sha1_checksum,strlen(new_msg.sha1_checksum),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report7");
		exit(EXIT_FAILURE);
	}

	snprintf(str,get_longint_len(new_msg.file_length),"%ld",new_msg.file_length);
	if(sendto(sock,str,strlen(str),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report8");
		exit(EXIT_FAILURE);
	}*/
	close(sock);
	pthread_exit(NULL);
	/*free(str);*/
}



/**Function of TCP Server*/
void* tcp_server(void* param){
	char buffer[512];
	char c;
  	int r;
  	int sock;
	int accepted;
	int *port=(int*)param;
	 FILE *fs;
	full_msg msg;
	full_msg received;
	struct sockaddr_in sin;

	struct sockaddr client_addr;
	socklen_t client_addr_len;  
	if((sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) == -1){
		perror("opening TCP socket");
		exit(EXIT_FAILURE);
	}
	  
	memset(&sin, 0, sizeof(struct sockaddr_in));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(*port);
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
	printf("\nTCP SERVER RUNS %d\n",*port);
	tcp_flag=1;
	client_addr_len = sizeof(struct sockaddr);
	while((accepted = accept(sock, &client_addr, &client_addr_len)) > 0 ){
		printf("New connection accepted!\n");
		r = recv(accepted,&received, sizeof(msg), 0);
		if(received.msg_type==FILE_TRANSFER_REQUEST){
		 	fs=fopen(strcat(watched_dir,received.file_name),"r");
			flock(fileno(fs),LOCK_EX);
    			while((c=getc(fs))!=EOF)
    			{
        			printf("%c",c);
				write(accepted,&c,1);
    			}
    			flock(fileno(fs),LOCK_UN);
    			fclose(fs); 
		}
		printf(" \n TSP SERVER %d TYPE\n",received.msg_type);
		message_interpretation(received);
		   
		close(accepted);
	}
	pthread_exit(NULL);
}

/*Function of UDP Server usinig threads*/
/*jagathan*/
void* udp_server(void* param){	
	char buffer[512];  
	int sock;
	/*int accepted;*/
	int r;
	full_msg received=*(full_msg*)malloc(sizeof(full_msg));
	//full_msg* msg=(full_msg*)param;
	//int port=msg->TCP_listening_port;
	int *port=(int*)param;	
	struct sockaddr_in sin;
	socklen_t srcaddrSize= sizeof(struct sockaddr_in);
	/* UNUSED VARS
	struct sockaddr client_addr;*/
	/*socklen_t client_addr_len;*/
	
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
		
	    	//memset(buffer, 0, 512);
		if((r =recvfrom(sock, &received, sizeof(received), 0, (struct sockaddr *) &sin, (socklen_t*) & srcaddrSize)) == -1){
			
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}	
		else{	
			broadcast_messages++;
		  	client_ip=(char*)malloc(sizeof(char*));
			strcpy(client_ip,inet_ntoa(sin.sin_addr));
			if(pthread_create(&new_thread, (void*)&thread_attributes,(void*) &udp_receiver_dispatcher_thread,&received)!= 0){
			 	perror("create thread");
			      	exit(EXIT_FAILURE);
			}
			
	        }
		/*if((r =recvfrom(sock, buffer, 511, 0, (struct sockaddr *) &sin, (socklen_t*) & srcaddrSize)) == -1){
			
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}	
		else{	
			client_ip=(char*)malloc(sizeof(char*));
			strcpy(client_ip,inet_ntoa(sin.sin_addr));
			buffer[r]=0;
			sscanf(buffer, "%hd", &received->msg_type);
			memset(buffer, 0, 512);
	        }
		if((r =recvfrom(sock, buffer, 511, 0,(struct sockaddr *) &sin, (socklen_t*) & srcaddrSize)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			received->client_name=(char*)malloc(strlen(buffer)*sizeof(char));
			strcpy(received->client_name,buffer);
			printf("\nSTRING %s\n",buffer);
			memset(buffer, 0, 512);
		}
		if((r =recvfrom(sock, buffer, 511, 0, (struct sockaddr *)&sin, (socklen_t*) & srcaddrSize)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			//sscanf(buffer, "%hd", &received->TCP_listening_port);
			received->TCP_listening_port=*port;
			printf("\n\n PORT %d\n\n",received->TCP_listening_port);
			memset(buffer, 0, 512);
		}
		if((r =recvfrom(sock, buffer, 511, 0,(struct sockaddr *) &sin, (socklen_t*) & srcaddrSize)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			sscanf(buffer,"%ld", &received->current_time_stamp);
			memset(buffer, 0, 512);
		}
		if((r =recvfrom(sock, buffer, 511, 0, (struct sockaddr *)&sin, (socklen_t*) & srcaddrSize)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			sscanf(buffer,"%ld", &received->file_mod_time_stamp);
			memset(buffer, 0, 512);
		}		
		if((r =recvfrom(sock, buffer, 511, 0,(struct sockaddr *) &sin, (socklen_t*) & srcaddrSize)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			received->file_name=(char*)malloc(strlen(buffer)*sizeof(char));
			strcpy(received->file_name,buffer);
			memset(buffer, 0, 512);
		}
		if((r =recvfrom(sock, buffer, 511, 0,(struct sockaddr *) &sin, (socklen_t*) & srcaddrSize)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			received->sha1_checksum=(char*)malloc(strlen(buffer)*sizeof(char));
			strcpy(received->sha1_checksum,buffer);
			memset(buffer, 0, 512);
		}
		if((r =recvfrom(sock, buffer, 511, 0,(struct sockaddr *) &sin, (socklen_t*) & srcaddrSize)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			new_thread = malloc(sizeof(pthread_t));
			sscanf(buffer,"%ld", &received->file_length);
			if(pthread_create(&new_thread, (void*)&thread_attributes,(void*) &udp_receiver_dispatcher_thread,(void*)received)!= 0){
			 	perror("create thread");
			      	exit(EXIT_FAILURE);
			}
		}*/
	
	}
	pause();
	pthread_exit(NULL);
	/*free(received);*/
}
/*jagathan*/
/*handles every client that connects*/
void* udp_receiver_dispatcher_thread(void *params){
	
	full_msg* msg=(full_msg*)params;
	full_msg new_msg;
	pthread_t thread_tcpclient; 
	pthread_attr_t thread_tcpclient_attributes;
	pthread_attr_setdetachstate(&thread_tcpclient_attributes, PTHREAD_CREATE_JOINABLE);
	new_msg=full_message_creator(msg->msg_type,msg->client_name,msg->TCP_listening_port, msg->current_time_stamp, 0, "","", -1);	
	message_interpretation(*msg);
	if(pthread_create(&thread_tcpclient, &thread_tcpclient_attributes, &tcp_client,&new_msg) != 0){
		perror("create thread udpclient");
		exit(EXIT_FAILURE);
	}
	//watched_files=check_changes(watched_files,msg);
	printf("\n\nMESA SE DISPATCH %d\n\n",new_msg.msg_type);
	/*if(pthread_create(&thread_tcpclient, &thread_tcpclient_attributes, &check_changes,&new_msg) != 0){
		perror("create thread udpclient");
		exit(EXIT_FAILURE);
	}*/
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

long int get_last_modified(char *file) {
    struct tm *clock,*clock1;
    struct stat attr;

    stat(file, &attr);
    clock = gmtime(&(attr.st_mtime));

    clock1 = mktime(clock);
   // printf("\nHumans Time:%s", asctime(clock));
    return mktime(clock);
}
char* get_current_time(){
	time_t rawtime;
	struct tm * timeinfo;
	time ( &rawtime );
	timeinfo = localtime ( &rawtime );
	return asctime (timeinfo) ;
}
/*end rafas function*/
int founded=0;
int flag=0;
int i=0;
int del=0;
void* scan_for_file_changes_thread(void* params){
	  	
	printf("\n\n");
	full_msg *msg=(full_msg*)params;
	full_msg new_msg;
	//=(full_msg*)malloc(sizeof(full_msg));
	char p[100];
	long long int clock;
	int fsize;
	DIR *fdir;
	struct dirent *ffiles,*lfiles;
	struct dir_files_status_list *cur=watched_files;
	int list_length=0;
	int check_dir=0;
	int modify=0;
	long int cur_time;
	pthread_t thread_udpclient; 
	pthread_attr_t thread_udpclient_attributes;
	flag=0;
	sscanf(get_current_time(),"%ld", &cur_time);
	//printf("TIME %s %ld",get_current_time(),cur_time);
	pthread_attr_init(&thread_udpclient_attributes);
	/*Set the detache state to JOINABLE*/
	pthread_attr_setdetachstate(&thread_udpclient_attributes, PTHREAD_CREATE_JOINABLE);

	pthread_mutex_lock(&file_list_mutex);
	//pthread_mutex_lock(&print_mutex);
	fdir=opendir(msg->file_name);
	if(!fdir){
		printf("\nThe directory path does not exists %s",msg->file_name);
		exit(-1);
	}
	//printf("\t\t\t\t\t\tStarts Checking of files %d\n",i);
	ffiles=readdir(fdir);
	//printf("\nTO PORT EINAI %d \n",msg->TCP_listening_port);
	while(ffiles){
		if((strcmp(ffiles->d_name,".")==0)||(strcmp(ffiles->d_name,"..")==0)){
			ffiles=readdir(fdir);
			continue;
		}
		list_length=0;
		strcpy(p,msg->file_name);
				
		strcat(p,ffiles->d_name);
		//printf("\n\nIN FUNCTION:File:  %s",ffiles->d_name);
		clock=get_last_modified(p);
		//printf("IN FUNCTION:Since the Epoch: [%lld seconds]\n",clock);
		fsize=filesize(p);
		compute_sha1_of_file(current_file.sha1sum,ffiles->d_name);/* added by jagathan */
		//printf("File size: %d bytes\n\n", fsize);
	        cur=watched_files;
		while(cur){	
			list_length++;
			if(!strcmp(ffiles->d_name,cur->filename)){
				check_dir++;
				//printf("Found [%s] int the list [%s]\n",ffiles->d_name,cur->filename);
				flag=2;
			}
		   	if(!strcmp(ffiles->d_name,cur->filename)){
		    		if(fsize!=cur->size_in_bytes){
					//printf("\nMPIKA1 %s %s",ffiles->d_name,cur->filename);
		      			modify=1;
		      			flag=4;//modify
		      			if(flag==4)printf("\n\n\nModify ena arxeio\n\n\n");
		      			cur->size_in_bytes=fsize;
					
		    		}
		    		if(clock!=cur->modifictation_time_from_epoch){
					//printf("\nMPIKA2");
					modify=1;
		       			flag=4;//modify
		       			if(flag==4)printf("\n\n\nModify ena arxeio\n\n\n");
		      			cur->modifictation_time_from_epoch=clock;
					
		    		}
		    		if(strcmp(current_file.sha1sum,cur->sha1sum)!=0){
					printf("\nMPIKA3");
		    	  		strcpy(cur->sha1sum,current_file.sha1sum);
					flag=4;
						
		   		}
				if(flag==4){
					new_msg=full_message_creator(FILE_CHANGED_MSG,msg->client_name,msg->TCP_listening_port, cur_time, clock, 
									msg->file_name,current_file.sha1sum, fsize);
					
					if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,&new_msg) != 0){
						perror("create thread udpclient");
				    		exit(EXIT_FAILURE);
			  		}
					
					
				}	
		   		 
		  	}
		  	cur=cur->next;
		}
			 
		if(flag==0)
		{	
			watched_files=insert_file(watched_files,ffiles->d_name,fsize,current_file.sha1sum,clock);
			//list_length++;
			flag=3;//add new file
		        if(flag==3){
	
				new_msg=full_message_creator(NEW_FILE_MSG,msg->client_name,msg->TCP_listening_port, cur_time, clock, ffiles->d_name,current_file.sha1sum, fsize);
				print_string(msg->client_name);
				if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,&new_msg) != 0){
					perror("create thread udpclient");
				    	exit(EXIT_FAILURE);
			  	}
			}
		}
		    
		flag=0;
		modify=0;
		ffiles=readdir(fdir);
	}
	close(fdir);
	if((!ffiles) && (list_length==0)){
		flag=1;//flag=1 not founded
		new_msg=full_message_creator(DIR_EMPTY, msg->client_name,msg->TCP_listening_port, cur_time, 0, msg->file_name,"-", 0);

		if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,&new_msg) != 0){
			perror("create thread udpclient");
		    	exit(EXIT_FAILURE);
	  	}
		
		
		return params;
	}
	if(list_length==check_dir && modify==0 && list_length!=0){//den eginan allages
	  	printf("\n\n\nDen eginan allages %s\n\n\n",msg->client_name);
		
		new_msg=full_message_creator(NO_CHANGES_MSG,msg->client_name,msg->TCP_listening_port, cur_time, clock, "","", 0);/* OXI SHA1 KAI OXI PROSFATO CLOCK*/
		if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,&new_msg) != 0){
			perror("create thread udpclient");
		    	exit(EXIT_FAILURE);
  		}
		
		
	}
	
	del=0;
	cur=watched_files;
	while(cur){ 
		del=0;
		printf("\nFILE NAME %s\n",msg->file_name);
	  	fdir=opendir(msg->file_name);
		if(!fdir){
			printf("\nThe directory path does not exist12 ");
			exit(-1);
		}
	  	lfiles=readdir(fdir);
	  	while(lfiles){
	   		if(!strcmp(lfiles->d_name,cur->filename)){
				//printf("Found [%s] in the dir [%s]\n",cur->filename,lfiles->d_name);
				del=1;
			}
	   
	   		lfiles=readdir(fdir);
	  	}
		if(del==0){
			printf("Not Found Must Be deleted(%s)\n",cur->filename);
	 	
			new_msg=full_message_creator(FILE_DELETED_MSG,msg->client_name,msg->TCP_listening_port, cur_time, clock, 
									cur->filename,current_file.sha1sum, fsize);
			watched_files=delete_file(watched_files,cur->filename);
			if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,&new_msg) != 0){
				perror("create thread udpclient");
			    	exit(EXIT_FAILURE);
		  	}
			
		
	  	}
	  cur=cur->next;		  
	}	
	pthread_mutex_unlock(&file_list_mutex);
	//pthread_mutex_unlock(&print_mutex);
	pause();
	printf("\n\n");
	i++;
	
	return params;
}
void* check_changes(void* params){
	struct dir_files_status_list *cur=watched_files;
	full_msg new_msg;//=(full_msg*)malloc(sizeof(full_msg));
	full_msg *msg=(full_msg*)params;
	pthread_t thread_tcpclient; 
	pthread_attr_t thread_tcpclient_attributes;
	pthread_attr_setdetachstate(&thread_tcpclient_attributes, PTHREAD_CREATE_JOINABLE);
	int ex=0;
	if(msg!=NULL){
	   	if(msg->msg_type==NO_CHANGES_MSG){
	  		printf("Kamia allagi!!!!!!!!!!!!!!!!!!!!!!!!!!!\n");
		  	return watched_files;
		}else if(msg->msg_type==NEW_FILE_MSG || msg->msg_type==FILE_CHANGED_MSG) {
		  	printf("\n\nPAKETO NEW FILE\n\n");
		 	while(cur){ 
		  		if(strcmp(cur->filename,msg->file_name)==0){
					//printf("Vrethike to name tou paketou stin lista (msg=%d)");
					ex=1;
		  		}
		  		else if(strcmp(cur->sha1sum,msg->sha1_checksum)==0){
				 	ex=1; 
				}
		   		cur=cur->next;		  
		  	}	
	  		if(ex==0){
	  			printf("Den Vrethike to name tou paketou stin lista (msg=%d)",ex);
	    			watched_files=insert_file(watched_files,msg->file_name,msg->file_length,msg->sha1_checksum,msg->file_mod_time_stamp);
				new_msg=full_message_creator(FILE_TRANSFER_REQUEST,msg->client_name,msg->TCP_listening_port, msg->current_time_stamp, msg->file_mod_time_stamp,
							     msg->file_name,msg->sha1_checksum, msg->file_length);
				printf("\n\nMESA SE CHANGES %d TYPE\n\n",new_msg.msg_type);
				if(pthread_create(&thread_tcpclient, &thread_tcpclient_attributes, &tcp_client,&new_msg) != 0){
					perror("create thread udpclient");
					(EXIT_FAILURE);
				}
	 	 	}
		}
		else if(msg->msg_type==FILE_DELETED_MSG){
		  	printf("\nDELETE FILE\n");
			watched_files=delete_file(watched_files,msg->file_name);
			remove(strcat(watched_dir,msg->file_name));
		}
	  
	}
	pthread_exit(NULL);
	return params;
}
void get_broadcast(){
	int fd;
	struct ifreq ifr;
	struct ifaddrs *ifa, *ifap;   
	struct sockaddr_in *sa;
	char *addr;
	char iface[] = "eth0";
	char* subnet_mask;
	char* broadcast_address;
	char* ip;
	  char addressOutputBuffer[INET6_ADDRSTRLEN];
	ip= (char*)malloc(sizeof(char*));
	broadcast_address=(char*)malloc(sizeof(char*));
	subnet_mask=(char*)malloc(sizeof(char*));
	/*find subnet mask*/
	if (getifaddrs(&ifap) == -1) {
               perror("getifaddrs");
               exit(EXIT_FAILURE);
        }  
	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {
		//if (ifa->ifa_ifu.ifu_broadaddr->sa_family == AF_INET) { 
			
			sa = ((struct sockaddr_in *) ifa->ifa_ifu.ifu_broadaddr);
			  addr=inet_ntop(ifa->ifa_ifu.ifu_broadaddr->sa_family,
                         &sa->sin_addr,
                         addressOutputBuffer,
                         sizeof(addressOutputBuffer));			
			//addr = inet_ntoa(sa->sin_addr);
			printf("\nBROADCAST \n",addr);
			if(strcmp(ifa->ifa_name,"eth0")==0){
				strcpy(broadcast_address,addr);
			}
		//}
	}
	/*find ip*/	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;

	strncpy(ifr.ifr_name , iface , IFNAMSIZ-1);
	 
	ioctl(fd, SIOCGIFADDR, &ifr);
	 
	close(fd);
	 
	//display result
	printf("\n%s - %s\n" , iface , inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr) );
	//printf("\n subent mask %s \n",subnet_mask); 
	strcpy(ip,inet_ntoa(( (struct sockaddr_in *)&ifr.ifr_addr )->sin_addr));
	//broadcast_address=ip | ( ~ subnet_mask );
	
	//printf("\n%s - %s\n" , iface , inet_ntoa((struct sockaddr_in *) &ifaddr->ifa_netmask ));
}
int main(int argc, char **argv){

	int opt;
	int scan_interval;
	int broadcast_port;
	int fsize=15;
	/*added now*/char p[100];
	char *client_name;
	char *watched_dir;
	broadcast_messages=0;
	full_msg *data_for_packet;
	DIR *dir;
        struct dirent *files;
	
	/*edited by jagathan*/
	pthread_t thread_udpserver;
  	pthread_t thread_udpclient;  
	pthread_t thread_tcpserver;
  	pthread_attr_t thread_udpserver_attributes;
  	pthread_attr_t thread_udpclient_attributes;
	pthread_attr_t thread_tcpserver_attributes;
	/*end -jagathan*/
	
	/*added by rafas*/long long int clock;
	
	watched_files=NULL;
	
	/*
	 * Initialize the mutexes
	 */
	pthread_mutex_init(&tcp_client_mutex, NULL);
	pthread_mutex_init(&print_mutex, NULL);
	pthread_mutex_init(&file_list_mutex, NULL);
	//get_broadcast();
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
	//full_msg full_test = full_message_creator(NEW_FILE_MSG, client_name, broadcast_port, 1548784512, 1548784512, watched_dir,"abcdefgghshjjdaaseee", 100);
	//message_interpretation(full_test);
	//full_test = full_message_creator(FILE_DELETED_MSG, client_name, broadcast_port, 1548784512, 1548784512, watched_dir,"abcdefgghshjjdaaseee", 100);
	//message_interpretation(full_test);
	/*AREA 51 TEST AREA!! PLEASE REMOVE "YOU DIDN'T SEE ANYTHING"*/
	
	/* Edited by jagathan */
	/*create the threads for udp server and client*/
	/* Initialize the attributes of the threads */
	pthread_attr_init(&thread_udpserver_attributes);
	pthread_attr_init(&thread_udpclient_attributes);
	pthread_attr_init(&thread_tcpserver_attributes);
	/*Set the detache state to JOINABLE*/
	pthread_attr_setdetachstate(&thread_udpserver_attributes, PTHREAD_CREATE_JOINABLE);
	pthread_attr_setdetachstate(&thread_udpclient_attributes, PTHREAD_CREATE_JOINABLE);
	pthread_attr_setdetachstate(&thread_tcpserver_attributes, PTHREAD_CREATE_JOINABLE);
	if(pthread_create(&thread_tcpserver, &thread_tcpserver_attributes, &tcp_server,(void*)&broadcast_port) != 0){
		perror("create thread udpserver");
	    	exit(EXIT_FAILURE);
  	}
	if(pthread_create(&thread_udpserver, &thread_udpserver_attributes, &udp_server,(void*)&broadcast_port) != 0){
		perror("create thread udpserver");
	    	exit(EXIT_FAILURE);
  	}
	while(tcp_flag==0){};
	dir=opendir(watched_dir);/*opens directory watched_dir and copies files in watched_files list*/
	/*added now*/strcat(watched_dir,"/");
	if(!dir){
		printf("\nThe directory path does not exist ");
		exit(-1);
	}
        files=readdir( dir);
	int cur_time=0;
	full_msg  new_msg;
        while(files){
		
                 /*Edit by Rafas*/
		if((strcmp(files->d_name,".")==0)||(strcmp(files->d_name,"..")==0)){
			files=readdir(dir);
			continue;
		}
		strcpy(p,watched_dir);		
		strcat(p,files->d_name);
		printf("File:  %s  %s\n",files->d_name,client_name);
		clock=get_last_modified(p);
		
		fsize=filesize(p);
		compute_sha1_of_file(current_file.sha1sum,files->d_name);/* added by jagathan */
		new_msg=full_message_creator(NEW_FILE_MSG,client_name,broadcast_port, cur_time, clock, files->d_name,current_file.sha1sum, fsize);
		if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,&new_msg) != 0){
			perror("create thread udpclient");
			exit(EXIT_FAILURE);
		}
                watched_files=insert_file(watched_files,files->d_name,fsize,current_file.sha1sum,clock);
                files=readdir(dir);
	
		/*End of Changes*/
      	}	

		
	while(1){
		data_for_packet=(full_msg*)malloc(sizeof(full_msg));
		data_for_packet->file_name=(char*)malloc(sizeof(char*));
		strcpy(data_for_packet->file_name,watched_dir);
		data_for_packet->file_name=watched_dir;
		data_for_packet->client_name=(char*)malloc(sizeof(char*));
		strcpy(data_for_packet->client_name,client_name);
		data_for_packet->TCP_listening_port=broadcast_port;
		if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &scan_for_file_changes_thread,(void*)data_for_packet) != 0){
			perror("create thread udpclient");
		    	exit(EXIT_FAILURE);
  		}
	  	sleep(scan_interval);
	}	
	pause();	
	/* end -jagathan*/
	return 0;
}

