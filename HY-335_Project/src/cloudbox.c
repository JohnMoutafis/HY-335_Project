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
	printf("\n\t\tUDP Packet received\n");
	//Message Cases
	if (incoming.msg_type == STATUS_MSG)
	{
		printf("\nSTATUS_MSG: 0x1\n");
		printf("Client name: %s\n",cname_tmp);
		printf("Port: %d\n",incoming.TCP_listening_port);
		printf("Client time: %ld\n",incoming.current_time_stamp);
	}
	else if(incoming.msg_type == NO_CHANGES_MSG)
	{
		printf("\nNO_CHANGES_MSG: 0x2\n");
		printf("Client name: %s\n",cname_tmp);
		printf("Port: %d\n",incoming.TCP_listening_port);
		printf("Client time: %ld\n",incoming.current_time_stamp);
		//printf("Sha1: %s\n",incoming.sha1_checksum);
	}
	else if(incoming.msg_type == NEW_FILE_MSG)
	{
		printf("\nNEW_FILE_MSG: 0x3\n");
		printf("Client name: %s\n",cname_tmp);
		printf("Port: %d\n",incoming.TCP_listening_port);
		printf("Client time: %ld\n",incoming.current_time_stamp);
		printf("File name: %s\n",fname_tmp);
		printf("File length: %ld\n",incoming.file_length);
	}
	else if(incoming.msg_type == FILE_CHANGED_MSG)
	{
		printf("\nFILE_CHANGED_MSG: 0x4\n");
		printf("Client name: %s\n",cname_tmp);
		printf("Port: %d\n",incoming.TCP_listening_port);
		printf("Client time: %ld\n",incoming.current_time_stamp);
		printf("File name: %s\n",fname_tmp);
		printf("File mod time: %ld\n",incoming.file_mod_time_stamp);
	}
	else if(incoming.msg_type == FILE_DELETED_MSG)
	{
		printf("\nFILE_DELETED_MSG: 0x5\n");
		printf("Client name: %s\n",cname_tmp);
		printf("Port: %d\n",incoming.TCP_listening_port);
		printf("Client time: %ld\n",incoming.current_time_stamp);
		printf("File name: %s\n",fname_tmp);
		printf("File mod time: %ld\n",incoming.file_mod_time_stamp);
		printf("File length: %ld\n",incoming.file_length);
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
		printf("DIR_EMPTY: 0x8\n");
		printf("Client name: %s\n",cname_tmp);
		printf("Port: %d\n",incoming.TCP_listening_port);
		printf("Client time %ld:",incoming.current_time_stamp);
		//printf("Sah1: %s\n\n",incoming.sha1_checksum);
	}
}
/*END OF MESSAGE FUNCTIONS*/

/**Function of TCP Client*/
void tcp_client(int port){
  
  int sock;
  //Added by Moutafis
  char buffer[512];
  int received;
 //end
  
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
  sin.sin_port = htons(port);
  /* The server's IP*/
  sin.sin_addr.s_addr = inet_addr("192.168.1.212");

  if(connect(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1){
    perror("tcp connect");
    exit(EXIT_FAILURE);
  }
  sleep(15);
  send(sock, "Hello Server!", 14, 0);
  //Added by Moutafis
  received = recv(sock,buffer,511,0);
  buffer[received] = 0;
  printf("Received from Server: %s\n",buffer);
  //end
  close(sock);
  
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
	
	int sock;
	full_msg* msg=(full_msg*)param;
	int port=msg->TCP_listening_port;
	char* str;
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
	str=(char*)malloc(sizeof(char*));
	snprintf(str,get_shortint_len(msg->msg_type),"%hd",msg->msg_type);
	if(sendto(sock,str,sizeof(str),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report1");
		exit(EXIT_FAILURE);
	}

	if(sendto(sock,msg->client_name,sizeof(msg->client_name),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report2");
		exit(EXIT_FAILURE);
	}
		
	snprintf(str,get_shortint_len(msg->TCP_listening_port),"%hd",msg->TCP_listening_port);
	if(sendto(sock,str,sizeof(str),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report3");
		exit(EXIT_FAILURE);
	}
	
	snprintf(str,get_longint_len(msg->current_time_stamp),"%ld",msg->current_time_stamp);
	if(sendto(sock,str,sizeof(str),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report4");
		exit(EXIT_FAILURE);
	}

	snprintf(str,get_longint_len(msg->file_mod_time_stamp),"%ld",msg->file_mod_time_stamp);
	if(sendto(sock,str,sizeof(str),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report5");
		exit(EXIT_FAILURE);
	}

	if(sendto(sock,msg->file_name,sizeof(msg->file_name),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report6");
		exit(EXIT_FAILURE);
	}

	if(sendto(sock,msg->file_name,sizeof(msg->sha1_checksum),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report7");
		exit(EXIT_FAILURE);
	}

	snprintf(str,get_longint_len(msg->file_length),"%ld",msg->file_length);
	if(sendto(sock,str,sizeof(str),0,(struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
		perror("send status report8");
		exit(EXIT_FAILURE);
	}
	close(sock);
	pthread_exit(NULL);
	/*free(str);*/
}



/**Function of TCP Server*/
void* tcp_server(void* param){
  char buffer[512];
  
  int sock;
  int accepted;
  int received;
  int *port=(int*)param;
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

  /* Ok, a tricky part here. See man accept() for details */

  client_addr_len = sizeof(struct sockaddr);
  while((accepted = accept(sock, &client_addr, &client_addr_len)) > 0 )
  {
    printf("New connection accepted!\n");
    received = recv(accepted, buffer, 511, 0);
    buffer[received] = 0;
    printf("Received from client: %s\n",buffer);
    //added by Moutafis
    int debug_size = sizeof("Debug Message.");
    send(sock, "Debug Message.", debug_size, 0);
    //end
    close(accepted);
  }
}

/*Function of UDP Server usinig threads*/
/*jagathan*/
void* udp_server(void* param){
	
	
	char buffer[512];  
	int sock;
	/*int accepted;*/
	int r;
	pthread_mutex_lock(&print_mutex);
	full_msg* received=(full_msg*)malloc(sizeof(full_msg));
	//full_msg* msg=(full_msg*)param;
	//int port=msg->TCP_listening_port;
	int *port=(int*)param;	
	struct sockaddr_in sin;
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

	    	memset(buffer, 0, 512);
		if((r =read(sock,buffer,511)) == -1){
			
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}	
		else{		
			buffer[r]=0;
			sscanf(buffer, "%hd", &received->msg_type);
			printf("\nMESSAGE %s ",buffer);
			memset(buffer, 0, 512);
	        }
		if((r =read(sock,buffer,511)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			received->client_name=(char*)malloc(strlen(buffer)*sizeof(char));
			strcpy(received->client_name,buffer);
			memset(buffer, 0, 512);
		}
		if((r =read(sock,buffer,511)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			sscanf(buffer, "%hd", &received->TCP_listening_port);
			memset(buffer, 0, 512);
		}
		if((r =read(sock,buffer,511)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			sscanf(buffer,"%ld", &received->current_time_stamp);
			memset(buffer, 0, 512);
		}
		if((r =read(sock,buffer,511)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			sscanf(buffer,"%ld", &received->file_mod_time_stamp);
			memset(buffer, 0, 512);
		}		
		if((r =read(sock,buffer,511)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			received->file_name=(char*)malloc(strlen(buffer)*sizeof(char));
			strcpy(received->file_name,buffer);
			memset(buffer, 0, 512);
		}
		if((r =read(sock,buffer,511)) == -1){
			perror("UDP read");
		  	exit(EXIT_FAILURE);
		}
		else{
			buffer[r]=0;
			received->sha1_checksum=(char*)malloc(strlen(buffer)*sizeof(char));
			strcpy(received->sha1_checksum,buffer);
			memset(buffer, 0, 512);
		}
		if((r =read(sock,buffer,511)) == -1){
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
		}
	
	}
	pause();
	pthread_mutex_unlock(&print_mutex);
	/*free(received);*/
}
/*jagathan*/
/*handles every client that connects*/
void* udp_receiver_dispatcher_thread(void *params){

	full_msg* msg=(full_msg*)params;	
	message_interpretation(*msg);
	//tcp_client(msg->TCP_listening_port);
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
	full_msg *new_msg=(full_msg*)malloc(sizeof(full_msg));
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
					printf("\nMPIKA1 %s %s",ffiles->d_name,cur->filename);
		      			modify=1;
		      			flag=4;//modify
		      			if(flag==4)printf("\n\n\nModify ena arxeio\n\n\n");
		      			cur->size_in_bytes=fsize;
					
		    		}
		    		if(clock!=cur->modifictation_time_from_epoch){
					printf("\nMPIKA2");
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
					*new_msg=full_message_creator(FILE_CHANGED_MSG,msg->client_name,msg->TCP_listening_port, cur_time, clock, 
									msg->file_name,current_file.sha1sum, fsize);
					
					if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,(void*)new_msg) != 0){
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
				printf("\n\n\nProstethike ena arxeio\n\n\n");
				
				*new_msg=full_message_creator(NEW_FILE_MSG,msg->client_name,msg->TCP_listening_port, cur_time, clock, msg->file_name,current_file.sha1sum, fsize);
			
				if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,(void*)new_msg) != 0){
					perror("create thread udpclient");
				    	exit(EXIT_FAILURE);
			  	}
				
		;
			}
		}
		    
		flag=0;
		modify=0;
		ffiles=readdir(fdir);
	}
	
	if((!ffiles) && (list_length==0)){
		flag=1;//flag=1 not founded
		*new_msg=full_message_creator(DIR_EMPTY, msg->client_name,msg->TCP_listening_port, cur_time, 0, msg->file_name,"-", 0);

		if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,(void*)new_msg) != 0){
			perror("create thread udpclient");
		    	exit(EXIT_FAILURE);
	  	}
		
		
		return params;
	}
	if(list_length==check_dir && modify==0 && list_length!=0){//den eginan allages
	  	printf("\n\n\nDen eginan allages %s\n\n\n",msg->client_name);
		*new_msg=full_message_creator(NO_CHANGES_MSG,msg->client_name,msg->TCP_listening_port, cur_time, clock, "","", 0);/* OXI SHA1 KAI OXI PROSFATO CLOCK*/
	
		if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,(void*)new_msg) != 0){
			perror("create thread udpclient");
		    	exit(EXIT_FAILURE);
  		}
		
		
	}
	
	
	/*if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,(void*)new_msg) != 0){
		perror("create thread udpclient");
	    	exit(EXIT_FAILURE);
  	}*/	
	del=0;
	cur=watched_files;
	while(cur){ 
		del=0;
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
	 		watched_files=delete_file(watched_files,cur->filename);
			*new_msg=full_message_creator(FILE_DELETED_MSG,msg->client_name,msg->TCP_listening_port, cur_time, clock, 
									msg->file_name,current_file.sha1sum, fsize);
			
			if(pthread_create(&thread_udpclient, &thread_udpclient_attributes, &udp_client,(void*)new_msg) != 0){
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


int main(int argc, char **argv){

	int opt;
	int scan_interval;
	int broadcast_port;
	int fsize=15;
	/*added now*/char p[100];
	char *client_name;
	char *watched_dir;
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
	//full_msg full_test = full_message_creator(NEW_FILE_MSG, client_name, broadcast_port, 1548784512, 1548784512, watched_dir,"abcdefgghshjjdaaseee", 100);
	//message_interpretation(full_test);
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
		if((strcmp(files->d_name,".")==0)||(strcmp(files->d_name,"..")==0)){
			files=readdir(dir);
			continue;
		}
		strcpy(p,watched_dir);		
		strcat(p,files->d_name);
		//printf("File:  %s",files->d_name);
		clock=get_last_modified(p);
		//printf("Since the Epoch: [%ld seconds]\n",clock);
		
		fsize=filesize(p);
		compute_sha1_of_file(current_file.sha1sum,files->d_name);/* added by jagathan */
		//printf("File size: %d bytes\n\n", fsize);
		
                watched_files=insert_file(watched_files,files->d_name,fsize,current_file.sha1sum,clock);
                files=readdir(dir);
          
		/*End of Changes*/
      	}	
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
	if(pthread_create(&thread_udpserver, &thread_udpserver_attributes, &udp_server,(void*)&broadcast_port) != 0){
		perror("create thread udpserver");
	    	exit(EXIT_FAILURE);
  	}
	/*if(pthread_create(&thread_tcpserver, &thread_tcpserver_attributes, &udp_server,(void*)&broadcast_port) != 0){
		perror("create thread udpserver");
	    	exit(EXIT_FAILURE);
  	}*/	
	while(1){
		data_for_packet=(full_msg*)malloc(sizeof(full_msg));
		data_for_packet->file_name=(char*)malloc(sizeof(char*));
		strcpy(data_for_packet->file_name,watched_dir);
		data_for_packet->file_name=watched_dir;
		data_for_packet->client_name=(char*)malloc(sizeof(char*));
		strcpy(client_name,client_name);
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
