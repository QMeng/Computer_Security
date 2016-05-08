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

#define PORT 8765

/* SSL for server side command line*/
#define FMT_ACCEPT_ERR "ECE568-SERVER: SSL accept error\n"
#define FMT_CLIENT_INFO "ECE568-SERVER: %s %s\n"
#define FMT_OUTPUT "ECE568-SERVER: %s %s\n"
#define FMT_INCOMPLETE_CLOSE "ECE568-SERVER: Incomplete shutdown\n"

void check_cert(ssl)
SSL *ssl;
{
    X509 *peer;
    char peer_CN[256];
    char peer_Email[256];

    //peer validation
    peer=SSL_get_peer_certificate(ssl);
    
    if(SSL_get_verify_result(ssl)!=X509_V_OK)
    {
        berr_exit(FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stdout);
        return;
    }
    
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_commonName, peer_CN, 256);
 
    X509_NAME_get_text_by_NID(X509_get_subject_name(peer),NID_pkcs9_emailAddress, peer_Email, 256);
         
    printf(FMT_CLIENT_INFO, peer_CN, peer_Email);   
}



int main(int argc, char **argv)
{
  int s, sock, port=PORT;
  
  /*define varibles for the CTX*/
  SSL_CTX *ctx;
  SSL *ssl;
  BIO *sbio;
  
  switch(argc){
    case 1:
      break;
    case 2:
      port=atoi(argv[1]);
      if (port<1||port>65535){
	fprintf(stderr,"invalid port number");
	exit(0);
      }
      break;
    default:
      printf("Usage: %s port\n", argv[0]);
      exit(0);
  }

  ctx=initialize_ctx("bob.pem","password");
  SSL_CTX_set_cipher_list(ctx, "SSLv2:SSLv3:TLSv1");
  SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, 0);

  if((sock=socket(AF_INET,SOCK_STREAM,0))<0){
    perror("socket");
    close(sock);
    exit(0);
  }
  
  struct sockaddr_in sin;
  memset(&sin,0,sizeof(sin));
  sin.sin_addr.s_addr=INADDR_ANY;
  sin.sin_family=AF_INET;
  sin.sin_port=htons(port);

  int val=1;
  setsockopt(sock,SOL_SOCKET,SO_REUSEADDR, &val,sizeof(val));
    
  if(bind(sock,(struct sockaddr *)&sin, sizeof(sin))<0){
    perror("bind");
    close(sock);
    exit (0);
  }
  
  if(listen(sock,5)<0){
    perror("listen");
    close(sock);
    exit (0);
  } 
  
  pid_t pid;

  //keep listening the client side input
  while(1){
    
    if((s=accept(sock, NULL, 0))<0){
      perror("accept");
      close(sock);
      close(s);
      exit (0);
    }
    
    if((pid=fork())){
      close(s);
    }
    else {
      //connect the child process
      printf("start forking a child\n");
      char buf[256];
      char *answer = "42";
      
      sbio=BIO_new_socket(s,BIO_NOCLOSE);
      ssl=SSL_new(ctx);
      SSL_set_bio(ssl,sbio,sbio);
      //accept handshake
      if(SSL_accept(ssl)<=0)
      {
        printf(FMT_ACCEPT_ERR);
        ERR_print_errors_fp(stdout);
        close(s);
        exit (0); 
      }
      check_cert(ssl);

      /*read the buffer from input*/
      int r, len;
      r=SSL_read(ssl,buf,256);
      buf[r] = '\0';
      switch(SSL_get_error(ssl,r)){
        case SSL_ERROR_WANT_READ:
          continue;
        case SSL_ERROR_NONE:
          len = r;
          break;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;
        case SSL_ERROR_SYSCALL:
          printf(FMT_INCOMPLETE_CLOSE);
          goto done;
        default:
          berr_exit("SSL read problem");
      }
      printf(FMT_OUTPUT, buf, answer);

      r=SSL_write(ssl,answer,strlen(answer));
      switch(SSL_get_error(ssl,r)){      
        case SSL_ERROR_NONE:
          if(strlen(answer)!=r)
          {
              err_exit("Incomplete write");
          }
          return 1;
        case SSL_ERROR_ZERO_RETURN:
          goto shutdown;

        case SSL_ERROR_SYSCALL:
          printf(FMT_INCOMPLETE_CLOSE);
          goto done;
        default:
              berr_exit("SSL write problem");
      }
      
      shutdown:
        r=SSL_shutdown(ssl);
        switch(r){
          case 1:
            break; /* Success */
          case 0:
          case -1:
          default:
            berr_exit("Shutdown failed");
        }
        
      done:
        SSL_free(ssl);
        close(s);
        return(0);
    }
  }
  destroy_ctx(ctx);
  close(sock);
  return 1;
}
