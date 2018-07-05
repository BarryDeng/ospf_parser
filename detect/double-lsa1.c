#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <regex.h>
#include <time.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "attack_origin.h"

#define PROGNAME double-lsa
#define MAX_TRACE_NUM 65536
#define MAX_LSA_NUM 20

#define MAXLINE 65536
#define PORT 8000

int next_begin;

enum {
    UDP_MODE, FILE_MODE
} run_mode;

struct detect_model
{
    struct timeval time; // 时间戳
    char interface_name[10]; // 接口名称
    char ip_src[16], ip_dst[16]; // IP地址
    enum {
        Hello, DD, LSU, LSA, LSR
    } ospf_type; // OSPF类型
    struct lsa {
        char adv_router[16]; // Adv_router
        uint32_t seq; // 序列号 
        enum {
            ROUTER_LSA = 1,
            NETWORK_LSA = 2,
            SUMMARY_LSA = 3,
            SUMMARY_LSA_2 = 4,
            AS_EXTERNAL_LSA = 5
        } lsa_type; // LSA类型
        char lsa_id[16]; // LSA-ID
    } LSAs[MAX_LSA_NUM];

} traces[MAX_TRACE_NUM];
int trace_num = 0;

struct detect_model characters; 

const char OSPF_TYPE[5][25] = { "Hello", "Database Description", "LS-Update", "LS-Ack", "LS-Request" };
const char LSA_TYPE[5][25] = {"Router LSA \\(1\\)", "Network LSA \\(2\\)", "Summary LSA \\(3\\)", "Summary LSA \\(4\\)", "AS External LSA"};

struct attack_record
{
	struct timeval time;
	char ls_id[16];
	uint32_t seq;
	char interface[10];
	char attacker[50];
	int enable;
} attack_records[100];

int attack_num = 0;

char* reg_match(const char *pattern, const char *str, int index)
{
    int status;
    regmatch_t pmatch[index + 1];
    const size_t nmatch = index + 1;
    regex_t reg;

    regcomp(&reg, pattern, REG_EXTENDED);

    status = regexec(&reg, str, nmatch, pmatch, 0);

    regfree(&reg);
    if (status == REG_NOMATCH) return NULL;

    char temp[25]; 
    strncpy(temp, &str[pmatch[index].rm_so], pmatch[index].rm_eo - pmatch[index].rm_so);
    temp[pmatch[index].rm_eo - pmatch[index].rm_so] = '\0';

    return strdup(temp);
}

int reg_match_index(const char *pattern, const char *str, const char (*template)[25], int size, int index)
{
    int cflags = REG_EXTENDED, status;
    regmatch_t pmatch[index + 1];
    const size_t nmatch = index + 1;
    regex_t reg;

    regcomp(&reg, pattern, cflags);

    status = regexec(&reg, str, nmatch, pmatch, 0);

    regfree(&reg);
    if (status == REG_NOMATCH) return -index;

    char temp[25]; 
    strncpy(temp, &str[pmatch[index].rm_so], pmatch[index].rm_eo - pmatch[index].rm_so);
    temp[pmatch[index].rm_eo - pmatch[index].rm_so] = '\0';

    for (int i = 0; i < size; ++i) 
    {
        if (!strcmp(template[i], temp)) 
        {
            return i;
        }
    }
    return -1;
}


void read_from_trace(char* line, int len)
{
    char *token = strtok(line, ";");
    int index = 0, reg_pos;
    char *reg_str;
    struct detect_model *temp = &traces[trace_num];
    while (token)
    {
        switch (index)
        {
            case 0:
                // strncpy(temp->time, strdup(token), sizeof(((struct detect_model*)0)->time));
                if (run_mode == UDP_MODE)
                {
                    gettimeofday(&temp->time, NULL);
                }
                sscanf(strdup(token), "%ld.%ld", &temp->time.tv_sec, &temp->time.tv_usec);
                break;
            case 1:
                // strncpy(temp->interface_name, strdup(token), sizeof(((struct detect_model*)0)->interface_name));
                sscanf(token, "%s", temp->interface_name);
                break;
            case 3:
                reg_str = reg_match("\\[IP\\] \\(([0-9.]+)\\) => \\(([0-9.]+)\\)\\(.+\\)", token, 1);
                if (reg_str)
                {
                    strncpy(temp->ip_src, reg_str, 16);
                }
                reg_str = reg_match("\\[IP\\] \\(([0-9.]+)\\) => \\(([0-9.]+)\\)\\(.+\\)", token, 2);
                if (reg_str)
                {
                    strncpy(temp->ip_dst, reg_str, 16);
                }

                break;
            case 5:
                reg_pos = reg_match_index("OSPFv[1-4], ([A-Za-z-]+), length [0-9]+", token, OSPF_TYPE, sizeof(OSPF_TYPE), 1); 
                temp->ospf_type = reg_pos;
                break;
            case 7:
                if (temp->ospf_type != 3) break;
                reg_str = reg_match("Advertising Router [0-9.]+, seq (0x[0-9a-f]+), age [0-9]+s, length [0-9]+", token, 1);
                if (reg_str != NULL)
                {
                    sscanf(reg_str, "%x", &temp->LSAs[0].seq);
                }
                break;

            case 8:

                if (temp->ospf_type == 3)
                {
                    char pattern[50];
                    for (int lsa_type = 0; lsa_type < sizeof(LSA_TYPE)/sizeof(LSA_TYPE[0]); ++lsa_type) {

                        snprintf(pattern, sizeof(pattern), "%s%s", LSA_TYPE[lsa_type], ", LSA-ID: ([0-9.]+)");
                        reg_str = reg_match(pattern, token, 1);

                        if (reg_str != NULL)
                        {
                            temp->LSAs[0].lsa_type = lsa_type + 1;
                            strncpy(temp->LSAs[0].lsa_id, reg_str, 16);
                            break;
                        }
                    }

                }
                reg_str = reg_match("Advertising Router [0-9.]+, seq (0x[0-9a-f]+), age [0-9]+s, length [0-9]+", token, 1);
                if (reg_str != NULL)
                {
                    sscanf(reg_str, "%x", &temp->LSAs[0].seq);
                }
                break;
            case 9:
                for (int lsa_type = 0; lsa_type < sizeof(LSA_TYPE)/sizeof(LSA_TYPE[0]); ++lsa_type) {
                    // printf("index: %d\n", lsa_type);
                    char pattern[50];
                    snprintf(pattern, sizeof(pattern), "%s%s", LSA_TYPE[lsa_type], ", LSA-ID: ([0-9.]+)");
                    reg_str = reg_match(pattern, token, 1);

                    if (reg_str != NULL)
                    {
                        temp->LSAs[0].lsa_type = lsa_type + 1;
                        strncpy(temp->LSAs[0].lsa_id, reg_str, 16);
                        break;
                    }
                }
                break;
            default:
                break;

        }
        // puts(token);
        token = strtok(NULL, ";");
        index++;
    } 

#ifdef DEBUG
    printf("%ld %s %s %s %d %d %x %s\n", temp->time.tv_sec, temp->interface_name, temp->ip_src, temp->ip_dst, temp->ospf_type, temp->LSAs[0].lsa_type, temp->LSAs[0].seq, temp->LSAs[0].lsa_id);
#endif

    trace_num++;
}

int alert(uint32_t a, char c[16], char interface[16], char src_ip[16], struct timeval time)
{
    static uint32_t record_a = 0;
    static char record_c[16] = { 0 };

#ifdef DEBUG
        printf("Interface: %s, SrcIP: %s\n", interface, src_ip);
#endif
 

    if (record_a == a && !strcmp(record_c, c))
    {
        // Omit repeat...
	    return 0;
    }
    else
    {
	struct attack_record *record = &attack_records[attack_num];
	record->enable = 1;
	record->time = time;
	record->seq = a;
	strncpy(record->ls_id, c, 16);
	strncpy(record->interface, interface, 10);
        printf("时刻%ld.%ld，链路 %s 上存在双LSA攻击，攻击源是 ", time.tv_sec, time.tv_usec, interface);

        int flag = 0;
        for (int i = 0; i < sizeof(attack_origins)/sizeof(attack_origins[0]); ++i)
        {
            if (!strcmp(attack_origins[i][0], interface) &&
                    !strcmp(attack_origins[i][1], src_ip))
            {
                printf("%s", attack_origins[i][2]);
		strncpy(record->attacker, attack_origins[i][2], 50);
                flag = 1;
                break;
            }
        }
	attack_num++;
        if (!flag)
            printf("未知");
        printf(" 。\n");
        record_a = a;
        strncpy(record_c, c, 16);
    }
    return 1;
}

int detect(int pos)
{
#ifdef DEBUG
    printf("BEGIN A NEW DETECT !\n");
#endif
    int detect_pos = 0;
    struct detect_model *temp;

    uint32_t ori_seq = 0;

    struct timeval b, j, n, f; // Timestamps
    uint32_t a, i, m, e; // Sequence Numbers
    char c[16], k[16], o[16], g[16]; // LSA IDs
    char d[16], l[16], p[16], h[16]; // Interface
    char y[16], z[16], u[16]; // Src Ip
    char x[16], w[16], v[16]; // Dst Ip
    int temp_begin;

    for (int index = pos; index < trace_num; ++index)
    {
        temp = &traces[index];
#ifdef DEBUG
        printf("%ld %s %s %s %d LSA_TYPE: %d %x %s\n", temp->time.tv_sec, temp->interface_name, temp->ip_src, temp->ip_dst, temp->ospf_type, temp->LSAs[0].lsa_type, temp->LSAs[0].seq, temp->LSAs[0].lsa_id);
        printf("Now Detect Pos: %d\n\n", detect_pos);
#endif

        switch (detect_pos)
        {
            case 0:
                if (temp->ospf_type == LSU && temp->LSAs[0].lsa_type == ROUTER_LSA)
                {
                    a = temp->LSAs[0].seq; // seq: a
                    b = temp->time; // timestamp: b
                    strncpy(c, temp->LSAs[0].lsa_id, 16); // ls_id: c
                    strncpy(d, temp->interface_name, 16); // interface: d
                    strncpy(u, temp->ip_src, 16); // src_ip: u 
                    strncpy(v, temp->ip_dst, 16); // dst_ip: v

		            temp_begin = index; // temp_begin: index
                    detect_pos = 3;
                }
                break;
            case 1:
                if (temp->ospf_type == LSU && temp->LSAs[0].lsa_type == ROUTER_LSA)
                {
                    i = temp->LSAs[0].seq; // seq: i
                    j = temp->time; // timestamp: j
                    strncpy(k, temp->LSAs[0].lsa_id, 16); // ls_id: k
                    strncpy(l, temp->interface_name, 16); // interface: l
                    strncpy(x, temp->ip_src, 16); // ip_src: x
                    strncpy(y, temp->ip_dst, 16); // ip_dst: y

                    if (!strcmp(d, l) && !strcmp(x, u)) 
                    {
                        if ( i == a + 1 && !strcmp(k, c))
                        { 
                            if (j.tv_sec - b.tv_sec > 1 && j.tv_sec - b.tv_sec < 5) 
                            {
                                detect_pos = 2;
                                break;
                            }
                        }
                        else 
                        {
                            if (j.tv_sec - b.tv_sec > 5)
                            {
                                detect_pos = 0;
                            }
                            else
                            {
                                detect_pos = 1;
                            }
                        }
                    }
                    else
                    {
                        detect_pos = 1;
                    }
                }
                break;
            case 2:
                if (temp->ospf_type == LSA)
                {
                    m = temp->LSAs[0].seq; // seq: m
                    n = temp->time; // timestamp: n
                    strncpy(o, temp->LSAs[0].lsa_id, 16); // ls_id: o
                    strncpy(p, temp->interface_name, 16); // interface: p
                    strncpy(z, temp->ip_src, 16); // ip_src: z

                    if (!strcmp(p, l) && !strcmp(z, y) && m == i && !strcmp(o, k))
                    {
                        alert(a, c, p, x, n);
			
		            next_begin = temp_begin + 1; // next_begin: pos
                            return 1;
                       
                    }
                    else
                    {
                        if (n.tv_sec - j.tv_sec > 2)
                        {
                            detect_pos = 0;
                        }
                        else
                        {
                            detect_pos = 2;
                        }
                    }
                }
                break;
            case 3:
                if (temp->ospf_type == LSA)
                {
                    e = temp->LSAs[0].seq; // seq: e
                    strncpy(g, temp->LSAs[0].lsa_id, 16); // ls_id: g
                    f = temp->time; // timestamp: f
                    strncpy(h, temp->interface_name, 16); // interface: h
                    strncpy(w, temp->ip_src, 16); // ip_src: w

                    // printf("DEBUG: n %x h %x m %s o %s\n", n, h, m ,o);
                    if (!strcmp(d, h) && !strcmp(v, w) && e == a && !strcmp(g, c))
                    {
                        detect_pos = 1;
                    }
                    else
                    {
                        if (f.tv_sec - b.tv_sec > 2)
                        {
                            detect_pos = 0;
                        }
                        else
                        {
                            detect_pos = 3;
                        }
                    }
                }
                break; 
            default:
                fputs("Detect Pos Error!\n", stderr);
                exit(-1);
        }
    }
    return 0;
}

void is_bonus(struct detect_model * temp)
{
	uint32_t q;
	struct timeval r;
	char s[16]; 

                if (temp->ospf_type == LSU && temp->LSAs[0].lsa_type == ROUTER_LSA)
                {
                    q = temp->LSAs[0].seq; // seq: q
                    r = temp->time; // timestamp: r
                    strncpy(s, temp->LSAs[0].lsa_id, 16); // ls_id: s
                   
		    for (int ind = 0; ind < attack_num; ++ind)
                    {
			   
			    struct attack_record *record = &attack_records[ind];
 			    if (!record->enable) continue;
		            if (r.tv_sec - record->time.tv_sec < 5)
		            {
		                if (!strcmp(s, record->ls_id) && q > record->seq)
		                {
		                    printf("时刻%ld.%ld，消除了攻击者 %s 对链路 %s 的双LSA攻击\n", r.tv_sec, r.tv_usec, record->attacker, record->interface);
		                    record->enable = 0;
		                }
		            }
                    }
                }

	
}

void udp_mode() 
{
    int sockfd;
    struct sockaddr_in servaddr, cliaddr;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);

    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htonl(INADDR_ANY);
    servaddr.sin_port = htons(PORT);

    if (bind(sockfd, (struct sockaddr *)&servaddr, sizeof(servaddr)) == -1)
    {
        perror("bind error");
        exit(1);
    }

    int n;
    socklen_t len;
    char mesg[MAXLINE];
    for (;;)
    {
        len = sizeof(cliaddr);
        n = recvfrom(sockfd, mesg, MAXLINE, 0, (struct sockaddr *)&cliaddr, &len);
        printf("%s\n", mesg);
        // sendto(sockfd, mesg, n, 0, (struct sockaddr *)&cliaddr, len);
        read_from_trace(mesg, len);
	is_bonus(&traces[trace_num - 1]);
        for (int i = next_begin; i < trace_num; ++i)
        {
            if(detect(i)) break;
        }
        memset(mesg, 0, sizeof(mesg));
    }
}

int main(int argc, char* argv[])
{
    char *line;
    size_t len = 0;

    // If no filename is specified, then run in udp mode.
    if (argc == 1)
    {
        run_mode = UDP_MODE;
        // printf("Usage: PROGNAME <filename>\n");
        // exit(1);
        udp_mode();
    }
    // Trace from file
    else if (argc == 2)
    {
        run_mode = FILE_MODE;
        // 打开文件
        FILE* fp;
        if ((fp = fopen(argv[1], "r")) == NULL)
        {
            fprintf(stderr, "File open failed!");
            exit(-1);
        }

        while (getline(&line, &len, fp) != -1)
        {
            // printf("%s\n", line);
            read_from_trace(line, len);
        }

        for (int i = next_begin; i < trace_num; ++i)
        {
            if(detect(i)) break;
        }

        free(line);
        line = NULL;

    } 
    else 
    {
        printf("Usage: PROGNAME <filename>\n");
        exit(-1);
    }
    return 0;
}
