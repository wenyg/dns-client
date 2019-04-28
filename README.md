### 简介
一个简单的DNS客户端,发送dns请求并解释响应.
```
#include <stdio.h>
#include "dns_client.h"

int main(int argc, char **argv)
{
	int result;
	result = dns_query("114.114.114.114", "www.baidu.com", TYPE_A, RPOTO_UDP, "53");
	if (result != DNS_SUCCESS)
	{
		printf("Someting wrong, error code: %d\n", result);
	}
	return 0;
}
```
### 例子

```
$ cd dns_client
$ make
$ ./query www.baidu.om
;;QUESTION: 
;www.baidu.com.                  IN        A

;;ANSWER SECTION:
www.baidu.com.           173     IN        CNAME     www.a.shifen.com.
www.a.shifen.com.        192     IN        A         115.239.211.112
www.a.shifen.com.        192     IN        A         115.239.210.27

```
### API说明
```
int dns_query(char *server_ip, char *domain, char *type, char *proto, char *port)
```
参数说明
- server_ip : dns服务器地址
- domain	: 要查询的域名
- type		: 要查询的域名类型,目前支持A,NS,MX,AAAA,SOA记录
- proto		: TCP还是UDP
- proto		: 服务器端口

