#include <stdio.h>
#include "dns_client.h"

int main(int argc, char **argv)
{
	int result;
	if (argc == 1)
	{	
		printf("query www.baidu.com @114.114.114.114:\n");
		result = dns_query("114.114.114.114", "www.baidu.com", TYPE_A, RPOTO_UDP, "53");
		goto end;
	}
	
	if (argc > 1)
	{
		result = dns_query("114.114.114.114", argv[1], TYPE_A, RPOTO_UDP, "53");
		goto end;
	}
	if (argc > 2)
	{
		result = dns_query("114.114.114.114", argv[1], argv[2], RPOTO_UDP, "53");
		goto end;
	}
	if (argc > 3)
	{
		result = dns_query(argv[3], argv[1], argv[2], RPOTO_UDP, "53");
		goto end;
	}

end:
	if (result != DNS_SUCCESS)
	{
		printf("Someting wrong, error code: %d\n", result);
	}
	return 0;
}