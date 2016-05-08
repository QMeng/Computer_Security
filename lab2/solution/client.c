#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "common.h"

#define HOST "localhost"
#define PORT 8765
#define EMAIL "ece568bob@ecf.utoronto.ca"
#define CLIENT_KEY_FILE "alice.pem"
#define SERVER "Bob's Server"

/*The instructions of clients*/
#define FMT_CONNECT_ERR "ECE568-CLIENT: SSL connect error\n"
#define FMT_SERVER_INFO "ECE568-CLIENT: %s %s %s\n"
#define FMT_OUTPUT "ECE568-CLIENT: %s %s\n"
#define FMT_CN_MISMATCH "ECE568-CLIENT: Server Common Name doesn't match\n"
#define FMT_EMAIL_MISMATCH "ECE568-CLIENT: Server Email doesn't match\n"
#define FMT_NO_VERIFY "ECE568-CLIENT: Certificate does not verify\n"
#define FMT_INCORRECT_CLOSE "ECE568-CLIENT: Premature close\n"




int check_cert(ssl)
SSL *ssl;
{
  char peer_CN[256];
  char peer_Email[256];
  char cert_Issuer[256];
  X509 *peer;
  
  //check peer certificate
  peer=SSL_get_peer_certificate(ssl);

  if(SSL_get_verify_result(ssl)!=X509_V_OK)
  {
    BIO_printf(bio_err,"%s\n",FMT_NO_VERIFY);
    ERR_print_errors(bio_err);
    exit(0);
    return 0;
  }

  X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
  X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_pkcs9_emailAddress, peer_Email, 256);
  X509_NAME_get_text_by_NID (X509_get_issuer_name(peer),NID_commonName,cert_Issuer,256);

  if(strcasecmp(peer_CN,SERVER))
  {
    BIO_printf(bio_err,"%s\n",FMT_CN_MISMATCH);
    ERR_print_errors(bio_err);
    exit(0);
    return 0;
  }

  if(strcasecmp(peer_Email,EMAIL))
  {
    BIO_printf(bio_err,"%s\n",FMT_EMAIL_MISMATCH);
    ERR_print_errors(bio_err);
    exit(0);
    return 0;
  }

  printf(FMT_SERVER_INFO,peer_CN,peer_Email,cert_Issuer);
  return 1;
}

int http_request(ssl,host,port,request)
 SSL *ssl;
 char *host;
 int port;
 char *request;
{
  char buf[256];
  int request_len=strlen(request);
  int r=SSL_write(ssl,request,request_len);
  
  switch(SSL_get_error(ssl,r))
  {
    case SSL_ERROR_NONE:
        if(request_len!=r)
        {
          fprintf(stderr,"%s\n","Incomplete write!");
          exit(0);
        }
        break;
      case SSL_ERROR_SYSCALL:
        printf("Close Error\n");
      	BIO_printf(bio_err,"%s\n",FMT_INCORRECT_CLOSE);
          	ERR_print_errors(bio_err);
         	exit(0);
        goto done;
      default:
	BIO_printf(bio_err,"%s\n","SSL write problem");
    	ERR_print_errors(bio_err);
   	exit(0);
  }

  while(1)
  {
   //write the message
   r=SSL_read(ssl,buf,256);
   switch(SSL_get_error(ssl,r)){
     case SSL_ERROR_NONE:
	buf[r]='\0';
	printf(FMT_OUTPUT, request, buf);
	return 1;
     case SSL_ERROR_ZERO_RETURN:
        goto shutdown;
     case SSL_ERROR_SYSCALL:
	BIO_printf(bio_err,"%s\n",FMT_INCORRECT_CLOSE);
    	ERR_print_errors(bio_err);
   	exit(0);
        goto done;
     default:
	BIO_printf(bio_err,"%s\n","SSL read problem");
    	ERR_print_errors(bio_err);
   	exit(0);
  }

 shutdown:
 printf("shutting down\n");
 r=SSL_shutdown(ssl);
 switch(r)
 {
   case 1:
	break; /* Success */
   case 0:
   case -1:
   default:
	BIO_printf(bio_err,"%s\n","Shutdown failed");
    	ERR_print_errors(bio_err);
   	exit(0);
 } 

 done:
 SSL_free(ssl);
 return(0);
  }
}

int main(int argc, char **argv)
{
  int len, sock, port=PORT;
  char *host=HOST;
  struct sockaddr_in addr;
  struct hostent *host_entry;
  char buf[256];
  char *secret = "What's the question?";
  
  /*initialize the CTX*/
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  
  
  switch(argc){
    case 1:
      break;
    case 3:
      host = argv[1];
      port=atoi(argv[2]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s server port\n", argv[0]);
      exit(0);
  }
  
  
  host_entry = gethostbyname(host);
  
  if (!host_entry){
    fprintf(stderr,"Couldn't resolve host");
    exit(0);
  }

  memset(&addr,0,sizeof(addr));
  addr.sin_addr=*(struct in_addr *) host_entry->h_addr_list[0];
  addr.sin_family=AF_INET;
  addr.sin_port=htons(port);
  /**/ 
  printf("Connecting to %s(%s):%d\n", host, inet_ntoa(addr.sin_addr),port);
  

  
  if((sock=socket(AF_INET, SOCK_STREAM, IPPROTO_TCP))<0)
    perror("socket");
  if(connect(sock,(struct sockaddr *)&addr, sizeof(addr))<0)
    perror("connect");
  
  /*Initialize SSL context*/
  ctx = initialize_ctx(CLIENT_KEY_FILE,"password");
  SSL_CTX_set_cipher_list(ctx,"SHA1");
  SSL_CTX_set_options(ctx,SSL_OP_NO_SSLv2);

  
  //create a socket for the bio and ssl  
  sbio=BIO_new_socket(sock,BIO_NOCLOSE);
  ssl=SSL_new(ctx);
  SSL_set_bio(ssl,sbio,sbio);
  
  if(!(SSL_connect(ssl)>0))
  {
    printf(FMT_CONNECT_ERR);
    ERR_print_errors_fp(stdout);
    goto done;
  }
  
  if(check_cert(ssl))
  {
   int res=http_request(ssl,host,port,secret);
   //finish the task 
  printf("Finish task\n");
   if(res) goto done;
   else {    
       return 0;
   }
  }
  printf("Finish task\n");
  done:
  SSL_CTX_free(ctx);
  close(sock);
  return 1;
}