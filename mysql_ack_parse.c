#include <stdio.h>
#include <string.h>  
#include <stdlib.h>  
#include <pcap.h>  


#include "mysql_ack_parse.h"
#include "parse_mysql_data.h"
#include "tool.h"

	


/* parse ethernet,ipv4,tcp header */
int parse_fixed_header(const u_char *package_data,
									u_int *p_cursor,
									u_int package_size,
									Global_variable *_Global)
{
	int a;
	
	/* ethernet header */
	if(*p_cursor + sizeof(Proto_Ethernet_Data) > package_size)
	{
		dump("cursor overflow!!\n");
		return -1;
	}
	memcpy(&_Global->ethernet_data, package_data + *p_cursor, sizeof(Proto_Ethernet_Data));
	*p_cursor += sizeof(Proto_Ethernet_Data);
	
	/* unsupport protocol */
	if(_Global->ethernet_data.ip_type != TCP_PROTOCOL)
	{
		dump("is not ipv4 protocol!!\n");
		return -4;
	}
	
	/* ipv4 header */
	memcpy(&_Global->ipv4_header, package_data + *p_cursor, sizeof(Proto_Ipv4_Header));
	*p_cursor = *p_cursor + _Global->ipv4_header.ip_header_len*sizeof(u_int);
	if(*p_cursor > package_size)
	{
		dump("cursor overflow!!\n");
		return -2;
	}
	
	/* tcp header */
	memcpy(&_Global->tcp_header, package_data + *p_cursor, sizeof(&_Global->tcp_header));
	*p_cursor = *p_cursor + _Global->tcp_header.header_len*sizeof(u_int);
	
	/* 纯ack包在此返回 */
	if(*p_cursor >= package_size)
	{
		dump("ack packet!!\n");
		return -3;
	}
	_Global->tcp_header.source_port = HTON16(_Global->tcp_header.source_port);
	
	/* 源端口为3306可直接认为是mysql应答包 */
	if(_Global->tcp_header.source_port == MYSQL_PORT)
	{
		_Global->mysql_flag = 1;
	}
	
	return 0;
}



int parse_mysql_data(const u_char *package_data,
									u_int *p_cursor,
									u_int package_size,
									Global_variable *_Global)
{
	MySQL_Header mysql_header;
	
	memset(&mysql_header, 0, sizeof(MySQL_Header));
	
	/* 解析应答包 */
	while(*p_cursor < package_size)
	{
		/* mysql header */
		if(*p_cursor + sizeof(MySQL_Header) > package_size)
		{
			dump("cursor overflow!!\n");
			return -1;
		}
		memcpy(&mysql_header, package_data + *p_cursor, sizeof(MySQL_Header));
		*p_cursor += sizeof(MySQL_Header);
		
		_Global->packet_length = (u_int)MYSQL_INIT3(mysql_header.size);
		
		switch(package_data[*p_cursor])
		{
			case 0xff:			/* ERR */ 
				parse_err_package(package_data,p_cursor,package_size,_Global);
				break;
			case 0xfe:			/* EOF */
				parse_eof_package(package_data,p_cursor,package_size,_Global);
				break;
			case 0x00:			/* OK */
				parse_ok_package(package_data,p_cursor,package_size,_Global);
				break;
			default:			/* Respone Packet */
				parse_response_package(package_data,p_cursor,package_size,_Global);
				break;
		}
	}
	
	
	return 0;
}



/* collback function */
void parsePacket(u_char *global, const struct pcap_pkthdr *pkthdr, const u_char *pkt)
{
	int ret = 0;
	u_int cursor = 0, pkt_len = 0, pkt_caplen = 0;
	u_int package_size = 0;
	u_char *package_data = NULL;
	Global_variable *Global = NULL;
	
	package_data = (u_char *)pkt;
	package_size = pkthdr->caplen;
	cursor = 0;
	Global = (Global_variable *)global;
	
	/* 抓取的长度小于实际长度，记录dump文件标识错误 */
	if(pkthdr->caplen < pkthdr->len)
	{
		dump("*****capture length is cut,pkt maybe loss!*****\n");
	}
	
	
	
	return;
}



int main(int argc, char **argv) 
{    	
	/* pcap句柄 */
	pcap_t *descr = NULL;  
	char errbuf[PCAP_ERRBUF_SIZE];
	/* 全局变量结构体 */
	Global_variable _Global;

	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	memset(&_Global,0,sizeof(Global_variable));
	
	if(argc < 2)
	{
		usage(argv[0]);
		return 0;
	}  

	/* 打开离线文件获得此文件的句柄 */
	if((descr = pcap_open_offline(argv[argc-1],errbuf)) == NULL)    
	{
		printf("pcap_open_offline error！,%s\n",errbuf);
		return 0;
	}
	
	/* 读取每个数据包，通过回调函数对每个包进行操作 */
	pcap_loop(descr,50,parsePacket,(u_char *)&_Global);

	return 0;
}



/* 用法 */
void usage(char *prog)
{
	printf("\nDESCRIPTION:\n");
	printf("\tParse MySQL-Single-Ack Protocol\n\n");
	printf("\t┌──────────┬───────────┬──────────┐\n");
	printf("\t│  Author  │  Version  │   BUILD  │\n");
	printf("\t├──────────┼───────────┼──────────┤\n");
	printf("\t│   Duo    │   1.0.0   │ 2019-9-2 │\n");
	printf("\t└──────────┴───────────┴──────────┘\n");
	printf("\nUSAGE:\n\t%s [options] [pcap_file]\n",prog);
	printf("\nOPTIONS:\n");
	printf("\t --tds	only display tds-protocol\n");
	printf("\t --tcp	only display tcp-protocol\n");
	printf("\t --udp	only display udp-protocol\n");
	printf("\nEXAMPLE:\n");
	printf("\t%s sqlserver.pcap\n",prog);
	printf("\t%s --tds sqlserver.pcap\n",prog);
	printf("\t%s --udp sqlserver.pcap\n",prog);
	printf("\t%s --tcp sqlserver.pcap\n",prog);
	printf("\t%s /root/test.pcap\n",prog);

	exit(0);
}
