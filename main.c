#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <pcap.h>
#define  BUFF_SIZE   1460 // before 1024

typedef struct IPHeader{
    unsigned char Version : 4;
    unsigned char IHL : 4;
    unsigned char TOS;
    u_short TotalLen;
    unsigned short Identifi;
    unsigned char Flagsx : 1;
    unsigned char FlagsD : 1;
    unsigned char FlagsM : 1;
    unsigned int FO : 13;
    unsigned char TTL;
    unsigned char Protocal;
    unsigned short HeaderCheck;
    struct in_addr SrcAdd;
    struct in_addr DstAdd;
}IPH;
typedef struct TCPHeader{
    unsigned short SrcPort;
    unsigned short DstPort;
    unsigned int SN;
    unsigned int AN;
    unsigned char Offset : 4;
    unsigned char Reserved : 4;
    unsigned char FlagsC : 1;
    unsigned char FlagsE : 1;
    unsigned char FlagsU : 1;
    unsigned char FlagsA : 1;
    unsigned char FlagsP : 1;
    unsigned char FlagsR : 1;
    unsigned char FlagsS : 1;
    unsigned char FlagsF : 1;
    unsigned short Window;
    unsigned short Check;
    unsigned short UP;
}TCPH;

void help(){
    printf("Write Interface Name\n");
    printf("Sample : pcap_test ens33\n");
}
int main(int argc, char* argv[]){
    if (argc != 2){
        help();
        exit(1);
    }
    int client_socket;
    struct sockaddr_in server_addr;
    char buff[BUFF_SIZE];
    struct pcap_pkthdr* header;
    const u_char* packet;
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    IPH *tlen;
    TCPH *tcph;


    client_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if( -1 == client_socket){
        printf("socket error \n");
        exit(1);
    }
    printf("client\n");
    memset(&server_addr, 0, sizeof (server_addr));
    printf("bb\n");
    server_addr.sin_family = AF_INET;
    printf("cc\n");
    server_addr.sin_port = htons(9900);
    printf("dd\n");
    server_addr.sin_addr.s_addr = inet_addr("192.168.10.1");

    if(-1 == connect(client_socket, (struct sockaddr *)&server_addr, sizeof(server_addr))){
        printf("connect failed \n");
        exit(1);
    }
    printf("connect!\n");
    //pcap_test
    pcap_t* handle = pcap_open_live(dev, 1024, 1, 1000, errbuf);
    if (handle == NULL){
        printf("%s : %s \n", dev, errbuf);
        exit(1);
    }

    while(1){
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) exit(1);
        tlen = (IPH *)packet;
        packet +=(uint16_t)(tlen->IHL)*4; //+ip header
        tcph = (TCPH *)packet;
        packet += (uint16_t)(tcph->Offset *4); // +tcp header

        memcpy(buff, packet, sizeof(packet));
        if(-1 == send(client_socket, buff, sizeof (buff),0)){
            printf("send error \n");
            exit(1);
        }
        else printf("send \n");
    }
    printf("Real done finish\n");
    pcap_close(handle);
    close(client_socket);


}

