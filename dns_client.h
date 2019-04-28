#ifndef DNS_HEALTH_CHECK_H_H
#define DNS_HEALTH_CHECK_H_H

#define DNS_SUCCESS 0

#define PARAMETER_ERROR -1
#define QUARY_SEND_ERROR -2
#define RESPONSE_RECV_ERROR -3
#define TCP_CONNECT_ERROR -4
#define SOCKET_ERROR -5

#define TYPE_A          "A"
#define TYPE_NS         "NS"
#define TYPE_AAAA       "AAAA"
#define TYPE_CNAME      "CNAME"
#define TYPE_MX         "MX"
#define TYPE_SOA        "SOA"
#define TYPE_TXT        "TXT"

#define PROTO_TCP       "TCP"
#define RPOTO_UDP       "UDP"

int dns_query(char *server_ip, char *domain, char *type, char *proto, char *port);

#endif