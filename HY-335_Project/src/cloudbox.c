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

/*
 * The list that holds all the current watched files.
 * 
 * It is very convinient this list to be shorted by the file name
 * in order to be able to find immediatly inconsistencies,
 */
struct dir_files_status_list *watched_files;


/*
 * Print mutex, for printing nicely the messages from different threads
 */
pthread_mutex_t print_mutex;


/* 
 * Mutex used to protect the accesses from different threads
 * of the file list of the watched directory
 */
pthread_mutex_t file_list_mutex;



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
default_msg default_message_creator(msg_type_t msg, char* client_name, int TCP_lp, int curr_ts)
{
	default_msg ret;
	ret.msg_type = msg;
	ret.TCP_listening_port = TCP_lp;
	ret.current_time_stamp = curr_ts;

	int size_of_cname = strlen(client_name) + 2, i;
	char tmp[size_of_cname];
	tmp[0] = 0x0;
	for(i=1; i<=size_of_cname-2; i++)
	{
		tmp[i] = client_name[i-1];
	}
	tmp[size_of_cname-1] = 0x0;

	ret.client_name = tmp;
	return ret;
}

full_msg full_message_creator(default_msg def_msg, int file_mts, char* file_name, int file_lngh)
{
	full_msg ret;
	//ret.def_msg = def_msg;
	ret.file_mod_time_stamp = file_mts;
	ret.file_length = file_lngh;

	int size_of_fname = strlen(file_name) + 1, i;
	char tmp[size_of_fname];
	tmp[0] = 0x0;
	for(i=1; i<=size_of_fname; i++)
	{
		tmp[i] = file_name[i-1];
	}
	tmp[size_of_fname-1] = 0x0;

	ret.file_name = tmp;
	return ret;
}

/*END OF MESSAGE FUNCTIONS*/

/**Function of TCP Client*/
void tcp_client(){
  
  int sock;
  
  struct sockaddr *client_addr;
  socklen_t client_addr_len;

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

/**Function of UDP Client*/
void udp_client(){
  int sock;
  
  unsigned int i = 0;
  
  struct sockaddr *client_addr;
  socklen_t client_addr_len;

  if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
    perror("opening UDP socket");
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
    perror("udp connect");
    exit(EXIT_FAILURE);
  }

  
  while(i < 10){
    printf("Look me, look me I do not block!!!\n");
    if( sendto(sock, "Hello Server!", 14, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr)) == -1){
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

/**Function of UDP Server*/
void udp_server(){
   char buffer[512];
  
  int sock;
  int accepted;
  int received;
  struct sockaddr_in sin;

  struct sockaddr client_addr;
  socklen_t client_addr_len;

  
  if((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1){
    perror("opening UDP socket");
    exit(EXIT_FAILURE);
  }
  
  memset(&sin, 0, sizeof(struct sockaddr_in));
  sin.sin_family = AF_INET;
  sin.sin_port = htons(6886);
  /* Bind to all available network interfaces */
  sin.sin_addr.s_addr = INADDR_ANY;

  if(bind(sock, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) == -1){
    perror("UDP bind");
    exit(EXIT_FAILURE);
  }


  while(1){
    memset(buffer, 0, 512);
    if( (received = read(sock, buffer, 511)) == -1){
      perror("UDP read");
      exit(EXIT_FAILURE);
    }
    buffer[received] = 0;
    printf("Received: %s\n", buffer);
    printf("Going to sleep for 5 secs... Like a boss!\n");
    sleep(5);
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
	/*unsigned char test = Default_Message_Creator(NO_CHANGES_MSG,client_name,broadcast_port,"1548784512");
	printf("%s\n",test);*/
	default_msg test = default_message_creator(NO_CHANGES_MSG, client_name, broadcast_port, 1548784512);
	full_msg full_test = full_message_creator(test, 1550784512, watched_dir,454545445);
	long double test_int;
	printf("%d",sizeof(test_int));
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
  
		fsize=filesize(p);
		
		printf("File (%s) size: %d bytes\n",files->d_name, fsize);
		
                watched_files=insert_file(watched_files,files->d_name,fsize,"sha",0);
                files=readdir(dir);
                
                
                
		/*End of Changes*/
        }
        while(watched_files){/*prints watched_files list*/
                printf("\n%s",watched_files->filename);
                watched_files=watched_files->next;
        }

    udp_server();
    tcp_server();
    udp_client();
    tcp_client();
	return 0;
}
