#include <stdio.h>
#include <string.h>  
#include <stdlib.h>  
#include <pcap.h>  
#include <sys/time.h>
#include <time.h>
#include "parse.h"
	

#define FILESIZE 256
#define COLNAME 50
#define REASSEMBLED_PKT 10240
#define PS pkthdr->ts.tv_sec
#define PU pkthdr->ts.tv_usec
#define PL pkthdr->len
#define PC pkthdr->caplen
#define P  packet
#define PP reassembled_pkt

double center=0,first=0;

/* 全局标志指针 */
Fragment_flag sql_flag;
/* 全局变量 */
Global_variable _Global;

/* 重组包数组 */
u_char reassembled_pkt[REASSEMBLED_PKT];

static void usage(char *prog);

void stradd(u_char *dest, size_t l, const u_char *src, size_t n)
{
	size_t length = l;
	size_t i;
	
	for(i = 0; i < n; ++i)
	{
		dest[length + i] = src[i];
	}
	
	return;
}

/* 解析envchange-TOKEN */
void tds_response_envchange_parse(const u_char *packet_data)
{
	int length = 0, new_length = 0, old_length = 0, i;
	u_char *pkt = (u_char *)packet_data;	

	length = little_endian_sum(pkt, 2);
	pkt += 2;
	
	printf("      | Token length: %d\n",length);
	if(*pkt == 1)
	{
		printf("      | Type: Database (1)\n");
	}
	else if(*pkt == 2)
	{
		printf("      | Type: Language (2)\n");
	}
	else if(*pkt == 3)
	{
		printf("      | Type: Character set (3)\n");
	}
	else if(*pkt == 4)
	{
		printf("      | Type: Packet size (4)\n");
	}
	new_length = *++pkt;
	printf("      | New Value Length: %d\n",new_length);
	printf("      | New Value: ");
	
	for(i = 0,pkt++; i < new_length; ++i,pkt++)
	{
		if(isprint(*pkt))
		{
			printf("%c",*pkt);
		}else{
			printf("\\%u",*pkt);
		}
	}
	old_length = *pkt++;
	printf("\n      | Old Value Length: %d",old_length);

	if(old_length == 0)
	{
		return;
	}
	printf("\n      | Old Value: ");
	for(i = 0; i < old_length; ++i,pkt++)
	{
		if(isprint(*pkt))
		{
			printf("%c",*pkt);
		}else{
			printf("\\%03u",*pkt);
		}
	}
	putchar('\n');

	return;
}

/* 解析info-TOKEN */
void tds_response_info_parse(const u_char *packet_data)
{
	int length = 0, info_number = 0, num = 0,i;
	u_char *pkt = (u_char *)packet_data;	

	length = little_endian_sum(pkt, 2);
	pkt += 2;
	printf("      | Token length: %d\n",length);
	info_number = little_endian_sum(pkt, 4);
	printf("      | Info Number: %d\n",info_number);
	pkt += 4;
	printf("      | Error state: %d\n",*pkt++);
	printf("      | Class (Severity): %d\n",*pkt++);
	length = little_endian_sum(pkt, 2);
	pkt += 2;
	printf("      | Error message length: %d characters\n",length);
	printf("      | Error message [truncated]: ");

	for(i = 0; i < length; ++i,pkt++)
	{
		if(isprint(*pkt))
		{
			printf("%c",*pkt);
		}else{
			printf("\\%03u",*pkt);
		}
	}
	length = *pkt++;
	printf("\n      | Server name length: %d characters\n",length);
	printf("      | Server name: ");
	for(i = 0; i < length; ++i,pkt++)
	{
		if(isprint(*pkt))
		{
			printf("%c",*pkt);
		}else{
			printf("\\%03u",*pkt);
		}
	}
	printf("\n      | Stored Procedure name length: %d characters\n",*pkt++);
	printf("      | Line number: %d\n",*pkt);

	return;	
}

void tds_response_loginack_parse(const u_char *packet_data)
{
	int length = 0, i;
	u_char *pkt = (u_char *)packet_data;	
	
	length = little_endian_sum(pkt, 2);
	pkt += 2;
	printf("      | Token length: %d\n",length);
	printf("      | Interface: %d\n",*pkt++);
	printf("      | TDS version: 0x%02x%02x%02x%02x\n",*pkt,*(pkt+1),*(pkt+2),*(pkt+3));
	pkt += 4;
	printf("      | Server name: ");
	length = *pkt++;
	for(i = 0; i < length; ++i,pkt++)
	{
		if(isprint(*pkt))
		{
			printf("%c",*pkt);
		}
	}
	printf("\n      | VersionMark: %d\n",*pkt++);
	printf("      | MajorVer: %d\n",*pkt++);
	printf("      | MinorVer: %d\n",*pkt++);
	printf("      | BuildNum: %d\n",*pkt);
		
	return;
}

void tds_response_done_parse(const u_char *packet_data)
{
	int count = 0;
	u_char flag = 0;
	u_char *pkt = (u_char *)packet_data;	
	
	flag = little_endian_sum(pkt, 2);
	
	if(flag < 256)
	{
		printf("\n      | .... ...0 .%d%d%d %d%d%d%d = Status flags: 0x%03x", \
				(flag>>6)&(u_char)1,(flag>>5)&(u_char)1,(flag>>4)&(u_char)1, \
		(flag>>3)&(u_char)1,(flag>>2)&(u_char)1,(flag>>1)&(u_char)1,flag&(u_char)1,flag);
	}else{
		printf("\n      | .... ...1 .%d%d%d %d%d%d%d = Status flags: 0x%03x", \
				(flag>>6)&(u_char)1,(flag>>5)&(u_char)1,(flag>>4)&(u_char)1, \
		(flag>>3)&(u_char)1,(flag>>2)&(u_char)1,(flag>>1)&(u_char)1,flag&(u_char)1,flag);
	}

	if((flag & 1) == 0)
	{
		printf("\n         | .... .... .... ...0 = More: Final done token");
	}else{
		printf("\n         | .... .... .... ...1 = More: More tokens fallow");
	}

	if((flag & 2) == 0)
	{
		printf("\n         | .... .... .... ..0. = Error: No");
	}else{
		printf("\n         | .... .... .... ..1. = Error: Yes");
	}

	if((flag & 4) == 0)
	{
		printf("\n         | .... .... .... .0.. = Transaction in process: No");
	}else{
		printf("\n         | .... .... .... .1.. = Transaction in process: Yes");
	}

	if((flag & 8) == 0)
	{
		printf("\n         | .... .... .... 0... = Procedure: No");
	}else{
		printf("\n         | .... .... .... 1... = Procedure: Yes");
	}

	if((flag & 16) == 0)
	{
		printf("\n         | .... .... ...0 .... = Row count valid: Invalid");
	}else{
		printf("\n         | .... .... ...1 .... = Row count valid: Valid");
	}

	if((flag & 32) == 0)
	{
		printf("\n         | .... .... ..0. .... = Acknowledge ATTN: No");
	}else{
		printf("\n         | .... .... ..1. .... = Acknowledge ATTN: Yes");
	}

	if((flag & 64) == 0)
	{
		printf("\n         | .... .... .0.. .... = Event: No");
	}else{
		printf("\n         | .... .... .1.. .... = Event: Yes");
	}

	if((flag & 256) == 0)
	{
		printf("\n         | .... ...0 .... .... = Server Error: No");
	}else{
		printf("\n         | .... ...1 .... .... = Server Error: Yes");
	}

	pkt += 2;
	printf("\n      | Current SQL Token: 0x%02x%02x",*pkt++,*pkt++);
	count = little_endian_sum(pkt, 2);
	printf("\n      | Row count: %d\n",count);
	
	return;
}

void tds_response_colname_parse(const u_char *packet_data)
{
	int length = 0, col_length = 0, i = 1, j = 0, sum = 0;
	u_char *pkt = (u_char *)packet_data;	
	char colname[COLNAME];

	memset(colname, 0, sizeof(colname));

	_Global.colname_flag = pkt;
	length = little_endian_sum(pkt, 2);
	pkt += 2;
	printf("      | Token length - ColName: %d",length);
	for(; sum < length; sum += (col_length + 1))
	{
		col_length = *pkt++;
		for(j = 0; j < col_length; j++,pkt++)
		{
			colname[j] = *pkt;
		}

		if(col_length == 0)
		{
			printf("\n      | Column %d",i++);
		}else{
			printf("\n      | Column %d (%s)",i++,colname);
		}
		printf("\n         | Column length: %d",col_length);
		printf("\n         | Column name: %s",colname);
		memset(colname, 0, sizeof(colname));
	}
	putchar('\n');
	
	return;
}

void tds_response_colformat_parse(const u_char *packet_data)
{
	int length = 0, usertype = 0, colsum_len = 0, col_length = 0;
	int count = 1, sum = 0, j, flag = 0;
	char colname[COLNAME];
	u_char *pkt = (u_char *)packet_data, *column_data = NULL;

	memset(colname,0,sizeof(colname));
	length = little_endian_sum(pkt, 2);
	pkt += 2;
	_Global.coltype_flag = (u_char *)pkt;
	printf("      | Token length - ColFormat: %d\n",length);
	
	column_data = _Global.colname_flag;
	colsum_len = little_endian_sum(column_data, 2);
	column_data += 2;
	for(; sum < colsum_len; sum += (col_length + 1))
	{
		col_length = *column_data++;
		for(j = 0; j < col_length; j++,column_data++)
		{
			colname[j] = *column_data;
		}
		
		usertype = little_endian_sum(pkt, 4);
		pkt += 4;	
		flag = *pkt++;

		if(flag == 0x26)
		{	
			printf("      | Column %d (%s, INTNTYPE)\n",count++,colname);
			printf("         | ColFormat - Column Usertype: %d\n",usertype);
			printf("         | ColFormat - Column Datatype: INTNTYPE (38)\n");
			printf("         | ColFormat - Column size: %u\n",(u_char)(*pkt++));
		}
		else if(flag == 0x30)
		{	
			printf("      | Column %d (%s, INT1TYPE - Tinyint (1 byte))\n",count++,colname);
			printf("         | ColFormat - Column Usertype: %d\n",usertype);
			printf("         | ColFormat - Column Datatype: INT1TYPE (48)\n");
		}
		else if(flag == 0x34)
		{	
			printf("      | Column %d (%s, INT2TYPE - SmallInt (2 byte))\n",count++,colname);
			printf("         | ColFormat - Column Usertype: %d\n",usertype);
			printf("         | ColFormat - Column Usertype: INT2TYPE (52)\n");
		}
		else if(flag == 0x38)
		{	
			printf("      | Column %d (%s, INT4TYPE - int (4 byte))\n",count++,colname);
			printf("         | ColFormat - Column Usertype: %d\n",usertype);
			printf("         | ColFormat - Column Usertype: INT4TYPE (56)\n");
		}
		else if(flag == 0x27)
		{	
			printf("      | Column %d (%s, VARCHARTYPE - varchar)\n",count++,colname);
			printf("         | ColFormat - Column Usertype: %d\n",usertype);
			printf("         | ColFormat - Column Usertype: VARCHARTYPE (39)\n");
			printf("         | ColFormat - Column size: %u\n",(u_char)(*pkt++));
		}
		else if(flag == 0x2f)
		{	
			printf("      | Column %d (%s, CHARTYPE - char\n",count++,colname);
			printf("         | ColFormat - Column Usertype: %d\n",usertype);
			printf("         | ColFormat - Column Usertype: CHARTYPE (47)\n");
		}

		memset(colname, 0, sizeof(colname));
	}

	return;
}

void tds_response_row_parse(const u_char *packet_data)
{
	int length = 0, colsum_len = 0, col_length = 0;
	int count = 1, sum = 0, j, flag, buff = 0;
	char colname[COLNAME], row_data[256];
	u_char *pkt = (u_char *)packet_data, *column_data = NULL, *column_type = NULL;

	memset(colname,0,sizeof(colname));
	memset(row_data,0,sizeof(row_data));
	_Global.rowsum = 0;
	column_data = _Global.colname_flag;
	column_type = _Global.coltype_flag;
	colsum_len = little_endian_sum(column_data, 2);
	column_data += 2;
	for(; sum < colsum_len; sum += (col_length + 1))
	{
		col_length = *column_data++;
		for(j = 0; j < col_length; ++j)
		{
			colname[j] = *column_data++;
		}
		column_type += 4;
		flag = *column_type++;

		if(flag != 0x30 && flag != 0x34 && flag != 0x38)
		{
			length = *pkt++;
			column_type++;
			for(j = 0; j < length; ++j)
			{
				row_data[j] = *pkt++;
			}
			_Global.rowsum += (length+1);
		}
		
		if(flag == 0x26)
		{	
			printf("      | Field %d (INTNTYPE)\n",count++);
			printf("         | [Column name: %s]\n",colname);
			printf("         | Length: %d\n",length);
			buff = little_endian_sum((const u_char*)row_data, length);
			printf("         | Data: %d\n",buff);
		}
		else if(flag == 0x30)
		{	
			_Global.rowsum += 1;
			buff = little_endian_sum(pkt, 1);
			pkt += 1;
			printf("      | Field %d (INT1TYPE - Tinyint (1 byte))\n",count++);
			printf("         | [Data: %d]\n",buff);
		}
		else if(flag == 0x34)
		{
			_Global.rowsum += 2;
			buff = little_endian_sum(pkt, 2);
			 pkt += 2;
			printf("      | Field %d (INT2TYPE - SmallInt (2 byte))\n",count++);
			printf("         | [Column name: %s]\n",colname);
			printf("         | Data: %d\n",buff);
		}
		else if(flag == 0x38)
		{	
			_Global.rowsum += 4;
			buff = little_endian_sum(pkt, 4);
			pkt += 4;
			printf("      | Field %d (INT4TYPE - int (4 byte))\n",count++);
			printf("         | [Column name: %s]\n",colname);
			printf("         | Data: %d\n",buff);
		}
		else if(flag == 0x27)
		{	
			printf("      | Field %d (VARCHARTYPE - varchar)\n",count++);
			if(col_length != 0)
			{
				printf("         | [Column name: %s]\n",colname);
			}
			printf("         | Data: %s\n",row_data);
		}
		else if(flag == 0x2f)
		{	
			printf("      | Field %d (CHARTYPE - char)\n",count++);
			printf("         | [Column name: %s]\n",colname);
			printf("         | Data: %s\n",row_data);
		}

		memset(colname,0,sizeof(colname));
		memset(row_data,0,sizeof(row_data));
	}

	return;
}

void tds_response_order_parse(const u_char *packet_data)
{
	int i, length = 0;
	u_char *pkt = (u_char *)packet_data;	
	
	length = little_endian_sum(pkt, 2);
	pkt += 2;
	printf("      | Token length: %d\n",length);
	for(i = 0; i < length; ++i)
	{
		printf("      | Order Column: %d\n",*pkt++);
	}
}

int little_endian_sum(const u_char *packet_data,int num)
{
	if(num == 0)
	{
		return 0;
	}
	int val = 0;
	u_char *pkt = (u_char *)packet_data;	

	val = *pkt++;
	if(num == 1)
	{
		return val;
	}
	val += ((*pkt++) * 256);
	if(num == 2)	
	{
		return val;
	}
	val += ((*pkt++) * 65536);
	val += ((*pkt) * 16777216);

	return val;
}

/* 回调函数 解析数据包 */
void parsePacket(u_char *arg,const struct pcap_pkthdr *pkthdr,const u_char *P)     
{  
	int i,c = 0,*counter = (int *)arg;
	int sp = 0,dp = 0;
	char date[20];
	long seq = 0,ack = 0;
		
	memset(date, 0, sizeof(date));
	
	if(_Global.tds_flag == 1) 
	{
		if((P[12] == 8) && (P[13] == 0) && (P[23] == 6) && \
				 P[54] == 1 && P[55] == 1 && PL > 66){}
		else
		{
			(*counter)++;
			return;
		}
	}
	/* 设置第一个包的时间，作为基准 */
	if((*counter) == 0)			
	{
		first=(PS)+(PU/1000000.0);
		center=(PS)+(PU/1000000.0);
	}
	printf("\nPacket Nomber: %d\n", ++(*counter));
	if((P[12] == 8) && (P[13] == 0) && (P[23] == 6) && P[54] == 1 && P[55] == 1 && PL > 66)
	{
		printf("Packet Type: TDS\n");
	}
	else if((P[12] == 8) && (P[13] == 0) && (P[23] == 6))
	{
		printf("Packet Type: TCP\n");
	}
	else if(P[12] == 8 && P[13] == 0 && P[23] == 17)
	{
		printf("Packet Type: UDP\n");
	}
	else if(P[12] == 134 && P[13] == 221 && P[20] == 17)
	{
		printf("Packet Type: UDP\n");
	}
	else if(P[12] == 8 && P[13] == 6)
	{
		printf("Packet Type: ARP\n");
	}
	else if(P[12] == 134 && P[13] == 221 && P[20] == 58)
	{
		printf("Packet Type: ICMPv6\n");
	}

	/* hop by hop Option (0) */
	else if(P[12] == 134 && P[13] == 221 && P[20] == 0)	printf("Packet Type: ICMPv6\n");	
	/* 生成树协议 */
	else if(P[17] == 0 && P[18] == 0 && P[19] == 0)
	{
		printf("Packet Type: STP\n");
		printf("Frame %d: %d bytes on wire(%d bits), %d bytes captured (%d bits)\n", \
			*counter,PL,8*PL,PC,8*PC);
		printf("IEEE 802.3 Ethernet\n");
		printf("Logical-Link Control\n");
		printf("Spanning Tree Control\n\n");
		return ;
	}

	printf("Received Packet Size: %d\n", PL);  
	printf("Packet data:\n");  
	for (i=1;i<=PC;++i)
	{ 
		if((i%16-1) == 0)
		{
			if(c<16)
			printf("%03X0:  ",c);	
			else if(c<256)
			printf("%03X0:  ",c);
			c++;
		}
		printf("%02x ",P[i-1]);
		if(i%8 == 0 && i != 0)	printf("    ");
		if ((i%16 == 0 && i != 0) || i == PL)	printf("\n");  
	}
/************************************************信息输出区*************************************************/

	/* frame层 */
	printf("Frame %d: %d bytes on wire(%d bits), %d bytes captured (%d bits)\n", \
		*counter, PL, 8*PL, PC, 8*PC);
	strftime(date,sizeof(date),"%Y-%m-%d %T",localtime(&(PS)));
	printf("   | Arrival Time: %s.%06ld000 中国标准时间\n",date,PU);
	printf("   | Epoch Time: %lf000 seconds\n",(PS)+(PU/1000000.0));
	printf("   | [Time dalta from previous captured frame: %lf000 seconds]\n", \
							((PS)+((PU)/1000000.0))-center);
	printf("   | [Time dalta from previous displayed frame: %lf000 seconds]\n", \
							(PS+((PU)/1000000.0))-center);
	printf("   | [The since reference or first frame: %lf000 seconds]\n", \
							(PS+((PU)/1000000.0))-first);
	printf("   | Frame Number: %d\n",*counter);
	printf("   | Frame Length: %d bytes (%d bits)\n",PL,8*PL);
	printf("   | Capture Length: %d bytes (%d bits)\n",PC,8*PC);

	/* 以太层 */
	printf("Ethernet II: Src: %02x:%02x:%02x:%02x:%02x:%02x, ", \
						P[6],P[7],P[8],P[9],P[10],P[11]);
	printf("Dst: %02x:%02x:%02x:%02x:%02x:%02x\n", \
						P[0],P[1],P[2],P[3],P[4],P[5]);
	printf("   | Destination: %02x:%02x:%02x:%02x:%02x:%02x\n", \
						P[0],P[1],P[2],P[3],P[4],P[5]);
	printf("   | Source: %02x:%02x:%02x:%02x:%02x:%02x\n", \
						P[6],P[7],P[8],P[9],P[10],P[11]);
	
	/* 协议确认号 例如0800是IPV4 */
	/* 协议确认号 例如86dd是IPV6 */
	/* 协议确认号 例如0806是ARP  */
	if(P[12] == 8 && P[13] == 0)	printf("   | Type: IPv4 (0x0800)\n");	
	if(P[12] == 134 && P[13] == 221)printf("   | Type: IPv6 (0x86dd)\n");		

	/* ARP层 */
	if(P[12] == 8 && P[13] == 6)
	{
		printf("   | Type: ARP (0x0806)\n");
		printf("Address Resolution Protocol\n");
		printf("   | Hardware type: Ethernet (%d)\n",P[15]);
		printf("   | Protocol type: IPv4 (0x%02x%02x)\n",P[16],P[17]);
		printf("   | Hradware size: %d\n",P[18]);
		printf("   | Protocol size: %d\n",P[19]);
		if(P[21] == 1)		printf("   | Opcode: request (%d)\n",P[21]);
		else if(P[21] == 2)	printf("   | Opcode: reply (%d)\n",P[21]);
		else if(P[21] == 3)	printf("   | Opcode: RARP request (%d)\n",P[21]);
		else if(P[21] == 4)	printf("   | Opcode: RARP reply (%d)\n",P[21]);
		printf("   | Sender MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", \
							P[22],P[23],P[24],P[25],P[26],P[27]);
		printf("   | Sender IP address: %d.%d.%d.%d\n",P[28],P[29],P[30],P[31]);
		printf("   | Target MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n", \
							P[32],P[33],P[34],P[35],P[36],P[37]);
		printf("   | Target IP address: %d.%d.%d.%d\n\n",P[38],P[39],P[40],P[41]);

		return;
	}

	/* IPv4层 */
	if(P[12] == 8 && P[13] == 0)
	{
		printf("Internet Protocol Version 4, Src: %d.%d.%d.%d, ",P[26],P[27],P[28],P[29]);
		printf("Dst: %d.%d.%d.%d\n",P[30],P[31],P[32],P[33]);
		printf("   | 0100 .... = Version: %d\n",P[14]/16);
		printf("   | .... 0101 = Header Length: 20 bytes (%d)\n",P[14]%16);
		printf("   | Differentiated Services Field: 0x%02x\n",P[15]);
		printf("   | Total Length: %d\n",P[16]*256+P[17]);
		printf("   | Identification: 0x%02x%02x (%d)\n",P[18],P[19],P[18]*256+P[19]);
		printf("   | Flags: 0x%02x%02x, Don't fragment\n",P[20],P[21]);
		printf("   | Time to live: %d\n",P[22]);
		printf("   | Protocol: TCP (%d)\n",P[23]);
		printf("   | Header checksum: 0x%02x%02x [validation disabled]\n",P[24],P[25]);
		printf("   | Source: %d.%d.%d.%d\n",P[26],P[27],P[28],P[29]);
		printf("   | Destination: %d.%d.%d.%d\n",P[30],P[31],P[32],P[33]);
	}

	/* IPv6层 */
	if(P[12] == 134 && P[13] == 221)
	{	
		printf("Internet Protocol Version 6, Src: %02x%02x:%02x%02x:%02x%02x:%02x%02x:" \
				"%02x%02x:%02x%02x:%02x%02x:%02x%02x, ", \
				P[22],P[23],P[24],P[25],P[26],P[27],P[28],P[29], \
				P[30],P[31],P[32],P[33],P[34],P[35],P[36],P[37]);
		printf("Dst: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:" \
				"%02x%02x\n",P[38],P[39],P[40],P[41],P[42],P[43],P[44],P[45], \
						P[46],P[47],P[48],P[49],P[50],P[51],P[52],P[53]);
		printf("   | 0110 .... = Version: %d\n",P[14]/16);
		printf("   | .... 0000 0000 .... .... .... .... .... = Traffic Class: 0x%02x\n",P[15]);
		printf("   | .... .... .... 0000 0000 0000 0000 0000 = Flow Label: 0x%02x%02x\n", \
											P[16],P[17]);
		printf("   | Payload Length: %d\n",P[18]*256+P[19]);
		if(P[20] == 17)	printf("   | Next Header: UDP (17)\n");
		else if(P[20] == 6)	printf("   | Next Header: TCP (6)\n");
		else if(P[20] == 1)	printf("   | Next Header: ICMP (1)\n");
		else if(P[20] == 89)	printf("   | Next Header: OSPF (89)\n");
		else if(P[20] == 2)	printf("   | Next Header: IGMP (2)\n");
		else if(P[20] == 58)	printf("   | Next Header: ICMPv6 (58)\n");
		else if(P[20] == 0)	printf("   | Next Header: IPv6 Hop-by-Hop Option (0)\n");
	
		printf("   | Hop Limit: %d\n",P[21]);
		printf("   | Source: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:" \
					"%02x%02x\n",P[22],P[23],P[24],P[25],P[26],P[27],P[28],P[29], \
							P[30],P[31],P[32],P[33],P[34],P[35],P[36],P[37]);
		printf("   | Destination: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:" \
					"%02x%02x\n",P[38],P[39],P[40],P[41],P[42],P[43],P[44],P[45], \
							P[46],P[47],P[48],P[49],P[50],P[51],P[52],P[53]);
		if(P[20] == 0 && P[62] == 143)
		{
			printf("   | IPv6 Hop-by-Hop Option\n");
			printf("      | Next Header: ICMPv6 (58)\n");
			printf("      | Length: %d\n",P[55]);
			printf("      | Router Alert\n");
			printf("         | Type: Router Alert (0x%02x)\n",P[56]);
			printf("      	 | Length: %d\n",P[57]);
			printf("         | Router Alert: MLD (%d)\n",P[58]*256+P[59]);
			printf("      | PadN\n");
			printf("         | Type: PadN (0x%02x)\n",P[60]);
			printf("         | Length: %d\n",P[61]);
			printf("Internet Control Message Protocol v6\n");
			printf("   | Type: Multicast Listener Report Message v2 (143)\n");
			printf("   | Code: %d\n",P[63]);
			printf("   | Checknum: 0x%02x%02x [correct]\n",P[64],P[65]);
			printf("   | Reserved: %02x%02x\n",P[66],P[67]);
			printf("   | Number of Multicast Address Records: %d\n",P[68]*256+P[69]);
			printf("   | Record Type: Changed to 	exclude (%d)\n",P[70]);
			printf("   | Aux Data Len: %d\n",P[71]);
			printf("   | Number of sources: %d\n",P[72]*256+P[73]);
			printf("   | Multicast Address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:" \
					"%02x%02x:%02x%02x:%02x%02x\n",P[74],P[75],P[76],P[77],P[78], \
					P[79],P[80],P[81],P[82],P[83],P[84],P[85],P[86],P[87],P[88],P[89]);
		}

		if(P[20] == 58 && P[54] == 135)	
		{
			printf("Internet Control Message Protocol v6\n");
			printf("   | Type: Neighbor Solicitation (135)\n");
			printf("   | Code: %d\n",P[55]);
			printf("   | Checknum: 0x%02x%02x [correct]\n",P[56],P[57]);
			printf("   | Reserved: %02x%02x%02x%02x\n",P[58],P[59],P[60],P[61]);
			printf("   | Target Address: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:" \
					"%02x%02x:%02x%02x:%02x%02x\n",P[62],P[63],P[64],P[65],P[66], \
					P[67],P[68],P[69],P[70],P[71],P[72],P[73],P[74],P[75],P[76],P[77]);
			printf("   | ICMPv6 Option (Source link-layer address : %02x:%02x:%02x:%02x:" \
						"%02x:%02x\n\n",P[80],P[81],P[82],P[83],P[84],P[85]);
		}
	}
	
	/* UDP层 */
	if(P[12] == 8 && P[13] == 0 && P[23] == 17)
	{
		printf("User Datagram Protocol, Src Port: %d,Dst Port: %d\n", \
							P[34]*256+P[35],P[36]*256+P[37]);
		printf("   | Source Port: %d\n",P[34]*256+P[35]);
		printf("   | Destination Port: %d\n",P[36]*256+P[37]);
		printf("   | Lentgh: %d\n",P[38]*256+P[39]);
		printf("   | Checksum: 0x%02x%02x [unverified]\n",P[40],P[41]);
		printf("   | [Checksum Status: unverified]\n\n");
	}

	if(P[12] == 134 && P[13] == 221 && P[20] == 17)
	{
		printf("User Datagram Protocol, Src Port: %d,Dst Port: %d\n", \
							P[54]*256+P[55],P[56]*256+P[57]);
		printf("   | Source Port: %d\n",P[54]*256+P[55]);
		printf("   | Destination Port: %d\n",P[56]*256+P[57]);
		printf("   | Lentgh: %d\n",P[58]*256+P[59]);
		printf("   | Checksum: 0x%02x%02x [unverified]\n",P[60],P[61]);
		printf("   | [Checksum Status: unverified]\n\n");
	}

	/* TCP层 */
	if(P[12] == 8 && P[13] == 0 && P[23] == 6)
	{
		sp  = P[34]*256+P[35];
		dp  = P[36]*256+P[37];
		seq = (long)P[38]*16777216+P[39]*65536+P[40]*256+P[41];
		ack = (long)P[42]*16777216+P[43]*65536+P[44]*256+P[45];
		printf("Transmission Control Protocol, Src Port: %d, Dst Port: %d,seq: %ld," \
							" ack: %ld, len: %d\n",sp,dp,seq,ack,PL-54);
		printf("   | Source Port: %d\n",sp);
		printf("   | Destination Port: %d\n",dp);
		printf("   | [TCP Segment Len: %d]\n",PL-54);
		printf("   | Sequence number: %ld   (telative sequence number)\n",seq);
		printf("   | [Next sequence number: %ld   (telative sequence number)]\n",seq+PL-54);
		printf("   | Acknowledgment number: %ld   (telative ack number)\n",ack);
		printf("   | .... 0101 = Header Length: %d bytes (%d)\n",(P[46]/16)*4,P[46]/16);
		if(P[47] == 2)	printf("   | Flags: 0x%x%02x (SYN)\n",P[46]%16,P[47]);
		if(P[47] == 16)	printf("   | Flags: 0x%x%02x (ACK)\n",P[46]%16,P[47]);
		if(P[47] == 17)	printf("   | Flags: 0x%x%02x (FIN, ACK)\n",P[46]%16,P[47]);
		if(P[47] == 24)	printf("   | Flags: 0x%x%02x (PSH, ACK)\n",P[46]%16,P[47]);
		printf("   | Window size pkt: %d\n",P[48]*256+P[49]);
		printf("   | Checksum: 0x%02x%02x [unverified]\n",P[50],P[51]);
		printf("   | Urgent pointpr: %d\n",P[52]*256+P[53]);
#if 1
		/* TDS层 */
		if(P[46] == 0x80 && P[47] == 0x18)
		{
			int flag = 0;

			printf("   | Options: (12 bytes), No-Operation (NOP), No-Operation (NOP), " \
								"Timestamps\n");
			printf("      TCP Option - No-Operation (NOP)\n");
			printf("         | Kind: No-Operation (1)\n");
			printf("      TCP Option - No-Operation (NOP)\n");
			printf("         | Kind: No-Operation (1)\n");
			printf("      TCP Option - Timestamps: TSval %ld, TSecr %ld\n",P[58]*16777216 \
				+P[59]*65536+P[60]*256+P[61],P[62]*16777216+P[63]*65536+P[64]*256+P[65]);
			printf("         | Kind: Time Stamp Option (8)\n");
			printf("         | Length: 10\n");
			printf("         | Timestamp pkt: %ld\n",P[58]*16777216+P[59]*65536+ \
											P[60]*256+P[61]);
			printf("         | Timestamp echo reply: %ld\n",P[62]*16777216+P[63]*65536 \
											+P[64]*256+P[65]);
			printf("   | [SEQ/ACK analysis]\n");
			printf("   | [Timestamps]\n");
			printf("   | TCP payload (%d bytes)\n",PL-66);
			printf("   | [PDU Size: %d]\n",PL-66);
			printf("Tabular Data Stream\n");
			if(P[66] == 1)
			{
				printf("   | Type: SQL batch (%d)\n",P[66]);
			}
			else if(P[66] == 2)
			{
				printf("   | Type: TDS login (%d)\n",P[66]);
			}
			else if(P[66] == 3)
			{
				printf("   | Type: Remote Procedure Call (%d)\n",P[66]);
			}
			else if(P[66] == 4)
			{
				printf("   | Type: Response (%d)\n",P[66]);
			}
			else if(P[66] == 6)
			{
				printf("   | Type: Attention signal (%d)\n",P[66]);
			}
			else if(P[66] == 7)
			{
				printf("   | Type: Bulk load data. This type is used to send binary " \
								"data to the server (%d)\n",P[66]);
			}
			else if(P[66] == 14)
			{
				printf("   | Type: Transaction manager request (%d)\n",P[66]);
			}
			else if(P[66] == 17)
			{
				printf("   | Type: SSPI message (%d)\n",P[66]);
			}
			else if(P[66] == 18)
			{
				printf("   | Type: Pre-login message (%d)\n",P[66]);
			}
			else
			{
				printf("\nTDS type pkt is %d\n",P[66]);
			}

			flag = P[67];

			printf("   | Status: 0x%02x\n",flag);
			sql_flag.tds_frag_flag = (flag & (u_char)1);
			if((flag & 1) == 0)
			{
				printf("      | .... ...0 = End of message: False\n");
			}else{
				printf("      | .... ...1 = End of message: Ture\n");
			}

			if(((flag>>1) & 1) == 0)
			{
				printf("      | .... ..0. = Ignore this event: False\n");
			}else{
				printf("      | .... ..1. = Ignore this event: Ture\n");
			}
			
			if(((flag>>2) & 1) == 0)
			{
				printf("      | .... .0.. = Event notification: False\n");
			}else{
				printf("      | .... .1.. = Event notification: Ture\n");
			}

			if(((flag>>3) & 1) == 0)
			{
				printf("      | .... 0... = Reset connection: False\n");
			}else{
				printf("      | .... 1... = Reset connection: Ture\n");
			}

			if(((flag>>4) & 1) == 0)
			{
				printf("      | ...0 .... = Reset connection keeping transaction state: False\n");
			}else{
				printf("      | ...1 .... = Reset connection keeping transaction state: Ture\n");
			}

			printf("   | Length: %d\n",P[68]*256+P[69]);
			printf("   | SPID: %d\n",P[70]*256+P[71]);
			printf("   | Packet ID: %d\n",P[72]);
			printf("   | Window: %d\n",P[73]);
	//		printf("   | \n");
	
			/* 登录解析 */
			if(P[66] == 0x02)
			{
				if(sql_flag.tds_login > 0)
				{
					printf("\nContinue...\n");
					printf("   | login packet-Part %d in frame %d\n", \
										sql_flag.tds_login,*counter);
					printf("   | Language name length: %d\n",P[592-sql_flag.tds_login_curror]);
					printf("   | Notify client of language changes: yes\n");
					printf("   | Secure login: No\n");
					printf("   | Secure bulk copy: No\n");
					printf("   | High Availability login: No\n");
					printf("   | High Availability session id: %02x%02x%02x%02x%02x%02x\n", \
						P[599-sql_flag.tds_login_curror],P[600-sql_flag.tds_login_curror], \
						P[601-sql_flag.tds_login_curror],P[602-sql_flag.tds_login_curror], \
						P[603-sql_flag.tds_login_curror],P[604-sql_flag.tds_login_curror]);
					printf("   | Character set name length: %d\n",P[637-sql_flag.tds_login_curror]);
					printf("   | Notify client of character set changes: Yes\n");
					printf("   | Packet size length: %d\n",P[645-sql_flag.tds_login_curror]);
					printf("   | Packet size: %c%c%c\n\n",P[639-sql_flag.tds_login_curror], \
						P[640-sql_flag.tds_login_curror],P[641-sql_flag.tds_login_curror]);
					sql_flag.tds_login = 0;

					char buff = 0;
					if(_Global.print_flag == 0)
					{
						printf("\nPress enter to read single packet,Press 'c' to read all packets\n");
						while(1)
						{    
							buff = getchar();
							if(buff == '\n')
							{    
								break;
							}    
							else if(buff == 'c') 
							{    
								_Global.print_flag = 1; 
							}    
						} 
					}
   
					return;
					
				}
				printf("   | TDS 4 Login Packet\n");
				printf("      | HostName: ");
				for(i = 0; i < 30; i++)
				{
					if(P[74+i] == 0) break;
					printf("%c",P[74+i]);
				}	
				printf("\n      | Hostname length: %d",P[104]);
				printf("\n      | UserName: ");
				for(i = 0; i < 30; i++)
				{
					if(P[105+i] == 0) break;
					printf("%c",P[105+i]);
				}	
				printf("\n      | Username length: %d",P[135]);
				printf("\n      | Password: ");
				for(i = 0; i < 30; i++)
				{
					if(P[136+i] == 0) break;
					printf("%c",P[136+i]);
				}	
				printf("\n      | Password length: %d",P[166]);
				printf("\n      | Host Process Id: ");
				for(i = 0; i < 30; i++)
				{
					if(P[167+i] == 0) break;
					printf("%c",P[167+i]);
				}	
				printf("\n      | Host Process length: %d",P[197]);
				printf("\n      | Login Options");
				printf("\n      | Application name: ");
				for(i = 0; i < 30; i++)
				{
					if(P[214+i] == 0) break;
					printf("%c",P[214+i]);
				}	
				printf("\n      | Application name length: %d",P[244]);
				printf("\n      | Server name: ");
				for(i = 0; i < 30; i++)
				{
					if(P[245+i] == 0) break;
					printf("%c",P[245+i]);
				}	
				printf("\n      | Server name length: %d",P[275]);
				printf("\n      | Remote password");
				printf("\n         | Remote password length: %d",P[531]);
				printf("\n         | Remote password servername length: %d",P[276]);
				printf("\n         | Remote password password length: %d",P[277]);
				printf("\n         | Remote password password: ");
				for(i = 0; i < 30; i++)
				{
					if(P[278+i] == 0) break;
					printf("%c",P[278+i]);
				}	
				printf("\n      | Protocol version: %02x%02x%02x%02x",P[532],P[533],P[534],P[535]);
				printf("\n      | Protocol name: %02x%02x%02x%02x",P[536],P[537],P[538],P[539]);
				printf("\n      | Program name length: %d",P[546]);
				printf("\n      | Program version: %02x%02x%02x%02x",P[547],P[548],P[549],P[550]);
				printf("\n      | Login Options 2");
				printf("\n         | Convert shorts to longs: No");
				printf("\n         | Single (4 byte) float format: IEEE Little-endian (%d)",P[552]);
				printf("\n         | Short (4 byte) date format: Low integer first (%d)\n",P[553]);
				printf("\nTo be continued...\n");

				if(P[67] == 0)
				{
					sql_flag.tds_login++;
					sql_flag.tds_login_curror = PL - 66;
				}
			}

			/*
			{
				printf("\n      | : %d",P[275]);
				printf("\n      | : %d",P[275]);

				printf("\n      | Password length: ");
				for(i = 0; i < 30; i++)
				{
					if(P[74+i] == 0) break;
					printf("%c",P[74+i]);
				}	
			}
			*/

			/* TDS-response包 */
			else if(P[66] == 0x04)
			{
				int i,length = 75,hdr_length = 0;
				int caplen = (int)PC;
			
				/* 如果包分片，合成一个包来处理 */
				if(sql_flag.tds_frag_flag == 0)
				{
					int des_len = 0, src_len = 0;
					u_char *val = (u_char *)&P[68];
					
					src_len = (*val)*256+*(val+1)-8;
					val += 6;
					des_len = _Global.reassembled_flag;
					printf("des_len = %d, src_len = %d\n",des_len,src_len);
					printf("_Global.reass = %d\n\n\n\n",_Global.reassembled_flag);
					stradd(reassembled_pkt, des_len, val, src_len);
					_Global.reassembled_flag += src_len;
					printf("\nNot last buffer...\n\n");
					
					return;
				}

	
				if(reassembled_pkt[0] > 0)
				{
					int src_len = 0;
					u_char *val = (u_char *)&P[68];
			
					src_len = (*val)*256+*(val+1);
					val += 6;
					
					printf("\nLast buffer...\n");
					stradd(PP, _Global.reassembled_flag, val, src_len);
					_Global.reassembled_flag += src_len;
					length = 1;
					caplen = _Global.reassembled_flag;	
					sql_flag.tds_frag_flag = 1;

					while(1)
					{
						if(length >= caplen)
						{
							memset(reassembled_pkt, 0, sizeof(reassembled_pkt));
							break;
						}
						else if(PP[length-1] == 0xe3)
						{
							printf("\n   | EnvChange_TOKEN\n");
							tds_response_envchange_parse(&PP[length]);
						}
						else if(PP[length-1] == 0xab)
						{
							printf("\n   | Info_TOKEN\n");
							tds_response_info_parse(&PP[length]);
						}
						else if(PP[length-1] == 0xa8)
						{
							printf("\n   | AltFormat_TOKEN\n");
						}
						else if(PP[length-1] == 0xa7)
						{
							printf("\n   | AltName_TOKEN\n");
						}
						else if(PP[length-1] == 0xd3)
						{
							printf("\n   | AltRow_TOKEN\n");
						}
						else if(PP[length-1] == 0xa5)
						{
							printf("\n   | ColInfo_TOKEN\n");
						}
						else if(PP[length-1] == 0xa1)
						{
							printf("\n   | ColFormat_TOKEN\n");
							tds_response_colformat_parse(&PP[length]);
						}
						else if(PP[length-1] == 0xa0)
						{
							printf("\n   | ColName_TOKEN\n");
							tds_response_colname_parse(&PP[length]);
						}
						else if(PP[length-1] == 0xfd)
						{
							printf("\n   | Done_TOKEN");
							tds_response_done_parse(&PP[length]);
							length += 9;
							continue;
						}
						else if(PP[length-1] == 0xff)
						{
							printf("\n   | Doneinproc_TOKEN");
							tds_response_done_parse(&PP[length]);
							length += 9;
							continue;
						}
						else if(PP[length-1] == 0xfe)
						{
							printf("\n   | DoneProc_TOKEN");
							tds_response_done_parse(&PP[length]);
							length += 9;
							continue;
						}
						else if(PP[length-1] == 0xaa)
						{
							printf("\n   | Error_TOKEN\n");
						}
						else if(PP[length-1] == 0xad)
						{
							printf("\n   | LoginAck_TOKEN\n");
							tds_response_loginack_parse(&PP[length]);
						}
						else if(PP[length-1] == 0x78)
						{
							printf("\n   | Offset_TOKEN\n");
						}
						else if(PP[length-1] == 0xa9)
						{
							printf("\n   | Order_TOKEN\n");
							tds_response_order_parse(&PP[length]);
						}
						else if(PP[length-1] == 0x79)
						{
							int len = 0;
							printf("\n   | ReturnStatus_TOKEN\n");
							len = little_endian_sum((const u_char*)&PP[length], 4);
							printf("      | Value: %d\n",len);
							length += 5;
							continue;
						}
						else if(PP[length-1] == 0xac)
						{
							printf("\n   | ReturnValue_TOKEN\n");
						}
						else if(PP[length-1] == 0xd1)
						{
							printf("\n   | Row_TOKEN\n");
							tds_response_row_parse(&PP[length]);
							length += (_Global.rowsum+1);
							continue;
						}
						else if(PP[length-1] == 0xed)
						{
							printf("\n   | Sspi_TOKEN\n");
						}
						else if(PP[length-1] == 0xa4)
						{
							printf("\n   | TabName_TOKEN\n");
						}
						hdr_length = little_endian_sum(&PP[length], 2);
						length += (hdr_length+3);
					}
				}
								
				while(1)
				{
					if(length >= caplen)
					{
						break;
					}
					else if(P[length-1] == 0xe3)
					{
						printf("\n   | EnvChange_TOKEN\n");
						tds_response_envchange_parse(&P[length]);
					}
					else if(P[length-1] == 0xab)
					{
						printf("\n   | Info_TOKEN\n");
						tds_response_info_parse(&P[length]);
					}
					else if(P[length-1] == 0xa8)
					{
						printf("\n   | AltFormat_TOKEN\n");
					}
					else if(P[length-1] == 0xa7)
					{
						printf("\n   | AltName_TOKEN\n");
					}
					else if(P[length-1] == 0xd3)
					{
						printf("\n   | AltRow_TOKEN\n");
					}
					else if(P[length-1] == 0xa5)
					{
						printf("\n   | ColInfo_TOKEN\n");
					}
					else if(P[length-1] == 0xa1)
					{
						printf("\n   | ColFormat_TOKEN\n");
						tds_response_colformat_parse(&P[length]);
					}
					else if(P[length-1] == 0xa0)
					{
						printf("\n   | ColName_TOKEN\n");
						tds_response_colname_parse(&P[length]);
					}
					else if(P[length-1] == 0xfd)
					{
						printf("\n   | Done_TOKEN");
						tds_response_done_parse(&P[length]);
						length += 9;
						continue;
					}
					else if(P[length-1] == 0xff)
					{
						printf("\n   | Doneinproc_TOKEN");
						tds_response_done_parse(&P[length]);
						length += 9;
						continue;
					}
					else if(P[length-1] == 0xfe)
					{
						printf("\n   | DoneProc_TOKEN");
						tds_response_done_parse(&P[length]);
						length += 9;
						continue;
					}
					else if(P[length-1] == 0xaa)
					{
						printf("\n   | Error_TOKEN\n");
					}
					else if(P[length-1] == 0xad)
					{
						printf("\n   | LoginAck_TOKEN\n");
						tds_response_loginack_parse(&P[length]);
					}
					else if(P[length-1] == 0x78)
					{
						printf("\n   | Offset_TOKEN\n");
					}
					else if(P[length-1] == 0xa9)
					{
						printf("\n   | Order_TOKEN\n");
						tds_response_order_parse(&P[length]);
					}
					else if(P[length-1] == 0x79)
					{
						int len = 0;
						printf("\n   | ReturnStatus_TOKEN\n");
						len = little_endian_sum((const u_char*)&P[length], 4);
						printf("      | Value: %d\n",len);
						length += 5;
						continue;
					}
					else if(P[length-1] == 0xac)
					{
						printf("\n   | ReturnValue_TOKEN\n");
					}
					else if(P[length-1] == 0xd1)
					{
						printf("\n   | Row_TOKEN\n");
						tds_response_row_parse(&P[length]);
						length += (_Global.rowsum+1);
						continue;
					}
					else if(P[length-1] == 0xed)
					{
						printf("\n   | Sspi_TOKEN\n");
					}
					else if(P[length-1] == 0xa4)
					{
						printf("\n   | TabName_TOKEN\n");
					}
				//	printf("      | Token length: %d\n",P[length]);
					length += (P[length]+3);
				}
				
			}/* TDS-resopnse */
			
			/* SQL batch层 */
			else if(P[66] == 0x01)
			{
				int i, length = 0;
				u_char *val = NULL;
	
				val = (u_char *)&P[68];
				length = (*val)*256 + *(val+1)-8;
				val += 6;
				printf("   | TDS Query Packet\n");
				printf("      | Query: ");
				for(i = 0; i < length; ++i,val++)
				{
					if(isprint(*val))
					{
						printf("%c",*val);
					}
					else if(*val == 0x0d)
					{
						printf("\\r");
					}
					else if(*val = 0x0a)
					{
						printf("\\n");
					}
					else
					{
						printf(" ");
					}
				}
			}
			
			/* RPC层 */
			else if(P[66] == 0x03)
			{
				int length =0, bat_length = 0, rpc_length = 0;
				int opt_flag = 0, flag = 0, sum = 0;
				u_char *val = NULL;

				val = (u_char *)&P[74];
				length = *val++;
				printf("\n   | Remote Procedure Call\n");
				printf("      | Procedure length: %d\n",length);
				printf("      | Procedure name: ");
				for(i = 0; i < length; ++i)
				{
					if(isprint(*val))
					{
						printf("%c",*val++);
					}else{
						printf(" ");
					}
				}	
				putchar('\n');
				sum += (length+3);
				opt_flag = (*val++)*256+(*val++);
				printf("      | Option Flags: 0x%04x\n",opt_flag);

				if((opt_flag & 1) == 0)
				{
					printf("         | .... .... .... ...0 = RPC is sent with the \"with recompile\" option: No\n");
				}else{
					printf("         | .... .... .... ...0 = RPC is sent with the \"with recompile\" option: Yes\n");
				}

				if(((opt_flag>>1) & 1) == 0)
				{
					printf("         | .... .... .... ..0. = No metadata will be returned for the result set: False\n");
				}else{
					printf("         | .... .... .... ..0. = No metadata will be returned for the result set: True\n");
				}

				rpc_length = P[68]*256+P[69]-8;
				if(rpc_length > 14)	
				{
					int i, count = 1;
					while(1)
					{
						if(sum >= (rpc_length-5))
						{
							break;
						}

						val += 4;
						bat_length = *val++;
						printf("      | Parameter Data %d: ",count++);
						for(i = 0; i < bat_length; ++i)
						{
							if(isprint(*val))
							{
								printf("%c",*val++);	
							}else{
								printf(" ");
							}
						}
						putchar('\n');	
						sum += (bat_length+5);
					}
				}
				
			}
			
			else
			{
				printf("      | Unknown Data......\n");				
			}
			
		}/* TDS */
		
#endif
	}/* TCP */


/***********************************************************************************************************/		
	center=(PS*1.0+(PU/1000000.0));
	
	char buff = 0;
	if(_Global.print_flag == 0)
	{
		printf("\nPress enter to read single packet,Press 'c' to read all packets\n");
		while(1)
		{    
			buff = getchar();
			if(buff == '\n')
			{    
				break;
			}    
			else if(buff == 'c') 
			{    
				_Global.print_flag = 1; 
			}    
		} 
	}   

	_Global.colname_flag = NULL;
	_Global.coltype_flag = NULL;
	return;  
} 
  
int main(int argc, char *argv[]) 
{    	
	int count = 0,num = 0;  
	/* pcap句柄 */
	pcap_t *descr = NULL;  
	struct bpf_program program;
	char errbuf[PCAP_ERRBUF_SIZE],file_name[FILESIZE];
	char filter[FILESIZE],*p = NULL;

	memset(&sql_flag, 0, sizeof(Fragment_flag));
	memset(errbuf,0,PCAP_ERRBUF_SIZE);
	memset(filter,0,FILESIZE);
	memset(reassembled_pkt,0,REASSEMBLED_PKT);
	memset(&_Global,0,sizeof(Global_variable));
	
	if(argc < 2)
	{
		usage(argv[0]);
		return 0;
	}  

	/* 打开离线文件获得此文件的句柄 */
	if((descr=pcap_open_offline(argv[argc-1],errbuf)) == NULL)    
	{
		printf("%s\n",errbuf);
		return 0;
	}

	if(argc == 3 && strcmp(argv[1],"--tds"))
	{
		/* 过滤规则 */
		p = argv[1];
		p += 2;
		strcpy(filter,p);
		pcap_compile(descr,&program,filter,1,0xffffff00);
		pcap_setfilter(descr,&program);
	}

	if(strcmp(argv[1],"--tds") == 0)
	{
		_Global.tds_flag = 1;
	}
	
	/* 读取每个数据包，通过回调函数对每个包进行操作 */
	pcap_loop(descr,num,parsePacket,(u_char *)&count);

	return 0;  
}

/* 用法 */
static void usage(char *prog)
{
	printf("\nDESCRIPTION:\n");
	printf("\tParse Frequently-used Protocol(for example TCP, UDP, TDS, etc)\n\n");
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
