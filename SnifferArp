#include<stdio.h>
#include<string.h>
#include<pcap.h>
#include<sys/socket.h>
#include<netinet/in.h>
#include<netinet/if_ether.h>
#include<netinet/ip.h>
#include<netinet/udp.h>
#include<netinet/tcp.h>
#include<netinet/ip_icmp.h>
#define max 1024

int VerifieProtocole(u_char *argument,const struct pcap_pkthdr* pack,const u_char *content)
{
  int m=0,n;
	const u_char *buf,*iphead;
	u_char *p;
	struct ether_header *ethernet;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct icmphdr *icmp;
	buf=content;
	printf("--------------------------------------------------\n");
	printf("La frame est \n");
	while(m< (pack->len))
	{
		printf("%02x",buf[m]);
		m=m+1;
		if(m%16==0)
			printf("\n");
		else
			printf(":");
	}
	printf("\n");
	printf("Longeur de paquets %d\n",pack->len);
	printf("Recu a ..... %s",ctime((const time_t*)&(pack->ts.tv_sec))); 


	ethernet=(struct ether_header *)content;
	p=ethernet->ether_dhost;
	n=ETHER_ADDR_LEN;
	printf("MAC destination est:");
	do{
		printf("%02x:",*p++);
	}while(--n>0);
	printf("\n");
	p=ethernet->ether_shost;
	n=ETHER_ADDR_LEN;
	printf("MAC source est:");
	do{
		printf("%02x:",*p++);
	}while(--n>0);
	printf("\n");
	
	if(ntohs(ethernet->ether_type)==ETHERTYPE_IP)
	{
		printf("IP paquet:\n");
		ip=(struct iphdr*)(content+14);
		printf("IP Version:%d\n",ip->version);
		printf("TTL:%d\n",ip->ttl);
		printf("Source address:%s\n",inet_ntoa(ip->saddr));
		printf("Destination address:%s\n",inet_ntoa(ip->daddr));
		printf("Protocole:%d\n",ip->protocol);
		switch(ip->protocol)
		{
			case 6:
				printf("Ce Protocole est le type TCP\n");
				tcp=(struct tcphdr*)(content+14+20);
				printf("Source Port:%d\n",ntohs(tcp->source));
				printf("Destination Port:%d\n",ntohs(tcp->dest));
				printf("Sequence Number:%u\n",ntohl(tcp->ack_seq));
				break;
			case 17:
				printf("Ce protocole est le type UDP\n");
				udp=(struct udphdr*)(content+14+20);
				printf("Source port:%d\n",ntohs(udp->source));
				printf("Destination port:%d\n",ntohs(udp->dest));
				break;
			case 1:
				printf("Ce protocole est le type ICMP\n");
				icmp=(struct icmphdr*)(content+14+20);
				printf("ICMP Type:%d\n", icmp->type);
				switch(icmp->type)
				{
					case 8:
						printf("ICMP Echo Request Protocol\n");
						break;
					case 0:
						printf("ICMP Echo Reply Protocol\n");
						break;
					default:
						break;
				}
				break;
			default:
				break;
		}


	}
	else if(ntohs (ethernet->ether_type) == ETHERTYPE_ARP)
	{
		printf("Paquet ARP:\n");
		iphead=buf+14;
		if (*(iphead+2)==0x08)
		{
			printf("Source ip:\t %d.%d.%d.%d\n",iphead[14],iphead[15],iphead[16],iphead[17]);
			printf("Dest ip:\t %d.%d.%d.%d\n",iphead[24],iphead[25],iphead[26],iphead[27]);
			printf("ARP TYPE: %d (0:demande;1:response)\n",iphead[6]);

		}
	}
	return 0;
}
int main(int argc,char *argv[])
{
	if(argc!=2)
	{
		printf("%s <Nombre de demande>\n",argv[0]);
		return 0;
	}
	pcap_t *handle;
	pcap_if_t *alldev;
	pcap_if_t *p;
	char error[100];

	struct in_addr net_ip_addr;
	struct in_addr net_mask_addr;
	struct ether_header *ethernet;

	char *net_ip_string;
	char *net_mask_string;
	char *interface;
	u_int32_t net_ip;
	u_int32_t net_mask;

	struct pcap_pkthdr pack; 
	const u_char *content;

	int i=0,num;
	if(pcap_findalldevs(&alldev,error)==-1)
	{
		printf("Rien trouve les peripheriques\n");
		return 0;
	}
	for(p=alldev;p;p=p->next)
	{
		printf("%d:%s\n",++i,p->name);
		if(p->description)
		{
			printf("%s\n",p->description);
		}
	}
	if(i==1)
		interface=p->name;
	else
	{
		printf("Choisissez une interface pour utiliser:\n");
		scanf("%d",&num);
		if(num<1||num>i)
		{
			printf("Saisissez une bonne interface\n");
			return 0;
		}
		for(p=alldev,i=1;i<=num;p=p->next,i++)
			interface=p->name;
	}
	if((handle=pcap_open_live(interface,max,1,0,error))==NULL)
	{
		printf("%s\n",error);
		return 0;
	}
	if(pcap_lookupnet(interface,&net_ip,&net_mask,error)==-1)
	{
		printf("%s\n",error);
		return 0;
	}
	printf("L'interface est:%s\n",interface);
	net_ip_addr.s_addr=net_ip;
	net_ip_string=inet_ntoa(net_ip_addr);
	printf("IP est:%s\n",net_ip_string);
	net_mask_addr.s_addr=net_mask;
	net_mask_string=inet_ntoa(net_mask_addr);
	printf("MASK est:%s\n",net_mask_string);
	pcap_loop(handle,atoi(argv[1]),VerifieProtocole,NULL);
	pcap_freealldevs(alldev);
	return 1;
}
