#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#define SERVER_PORT 5432
#define MAX_LINE 80

int main(int argc, char * argv[])
{
    FILE *fp;
    struct hostent *hp;
    struct sockaddr_in sin;
    char *host;
    char *fname;
    char buf[MAX_LINE];
    char sendbuf[MAX_LINE+4];
    int s;
    int slen;
    char lineNum = 1;
    char recvBuf[MAX_LINE+1];
    int ack;
    
    struct timeval tv;
    tv.tv_sec = 0;
    tv.tv_usec = 1000;

    if (argc==3) {
        host = argv[1];
        fname= argv[2];
    }
    else {
        fprintf(stderr, "Usage: ./client_udp host filename\n");
        exit(1);
    }
    /* translate host name into peer’s IP address */
    hp = gethostbyname(host);
    if (!hp) {
        fprintf(stderr, "Unknown host: %s\n", host);
        exit(1);
    }

    fp = fopen(fname, "r");
    if (fp==NULL){
        fprintf(stderr, "Can't open file: %s\n", fname);
        exit(1);
    }

    /* build address data structure */
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    bcopy(hp->h_addr, (char *)&sin.sin_addr, hp->h_length);
    sin.sin_port = htons(SERVER_PORT);

    /* active open */
    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("Socket");
        exit(1);
    }

    socklen_t sock_len= sizeof sin;
    
    /* set socket open time */
    if (setsockopt(s,SOL_SOCKET, SO_RCVTIMEO,&tv,sizeof(tv)) < 0) {
        perror("PError");
    }
    
    /* main loop: get and send lines of text */
    while(fgets(buf, 80, fp) != NULL){
        slen = strlen(buf);
        buf[slen] ='\0';
	    memset(sendbuf, 0, sizeof sendbuf);
	    sendbuf[0] = lineNum;
	
	    strcat(sendbuf, buf);
	    //printf("line %d: = %s",lineNum, sendbuf);
	    
	    ack = 0;
	    while(ack == 0)
	    {
            memset(recvBuf, 0, sizeof recvBuf);
            if(sendto(s, sendbuf, strlen(sendbuf), 0, (struct sockaddr *)&sin, sock_len)<0){
                perror("SendTo Error\n");
                exit(1);
            }
            recvfrom(s, recvBuf, sizeof(recvBuf), 0, (struct sockaddr *)&sin, &sock_len);
            if(recvBuf[0] == lineNum)
                ack = 1;
        }
        
	    lineNum++;
        }
        *buf = 0x02;    
            if(sendto(s, buf, 1, 0, (struct sockaddr *)&sin, sock_len)<0){
            perror("SendTo Error\n");
            exit(1);
        }
        fclose(fp);
}

