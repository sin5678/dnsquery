dnsquery:dnsquery.c
	gcc -g -Wall -masm=intel  -lpcap dnsquery.c -o dnsquery
