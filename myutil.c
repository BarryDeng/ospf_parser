#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <netinet/in.h>
#include <bsd/string.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#define TOKBUFSIZE 128

#define EXTRACT_U_1(p)	(*(p))
#define EXTRACT_S_1(p)	((int8_t)(*(p)))

struct tok {
	unsigned int v;		/* value */
	const char *s;		/* string */
};

/*
 * Convert a token value to a string; use "fmt" if not found.
 */
const char *
tok2strbuf(const struct tok *lp, const char *fmt,
	   u_int v, char *buf, size_t bufsize)
{
	if (lp != NULL) {
		while (lp->s != NULL) {
			if (lp->v == v)
				return (lp->s);
			++lp;
		}
	}
	if (fmt == NULL)
		fmt = "#%d";

	snprintf(buf, bufsize, fmt, v);
	return (const char *)buf;
}

/*
 * Convert a token value to a string; use "fmt" if not found.
 * Uses tok2strbuf() on one of four local static buffers of size TOKBUFSIZE
 * in round-robin fashion.
 */
const char *
tok2str(const struct tok *lp, const char *fmt,
	u_int v)
{
	static char buf[4][TOKBUFSIZE];
	static int idx = 0;
	char *ret;

	ret = buf[idx];
	idx = (idx+1) & 3;
	return tok2strbuf(lp, fmt, v, ret, sizeof(buf[0]));
}

const char *
intoa(uint32_t addr)
{
	char *cp;
	u_int byte;
	int n;
	static char buf[sizeof(".xxx.xxx.xxx.xxx")];

	addr = ntohl(addr);
	cp = buf + sizeof(buf);
	*--cp = '\0';

	n = 4;
	do {
		byte = addr & 0xff;
		*--cp = byte % 10 + '0';
		byte /= 10;
		if (byte > 0) {
			*--cp = byte % 10 + '0';
			byte /= 10;
			if (byte > 0)
				*--cp = byte + '0';
		}
		*--cp = '.';
		addr >>= 8;
	} while (--n > 0);

	return cp + 1;
}

const char *
ipaddr_string(const u_char *ap)
{
	uint32_t addr;

	memcpy(&addr, ap, sizeof(addr));

	return strdup(intoa(addr));
}

void
safeputchar(const u_char c)
{
	printf("\\0x%02x", c);
}

void
safeputs(const u_char *s, const u_int maxlen)
{
	u_int idx = 0;

	while (idx < maxlen && EXTRACT_U_1(s)) {
		safeputchar(EXTRACT_U_1(s));
		idx++;
		s++;
	}
}

/*
int
print_unknown_data(const u_char *cp,const char *ident,int len)
{
	// Now we don't need this function
	return 0;	

	if (len < 0) {
          printf("%sDissector error: print_unknown_data called with negative length",
		    ident);
		return(0);
	}
	
        // hex_print(ndo, ident,cp,len);
	for (int i = 0; i < len; i += 2)
	{
		if (i % 0x10 == 0) fprintf(server_sock, "\n\t    0x%04x:  ", i);
		fprintf(server_sock, "%02x%02x ", cp[i], cp[i + 1]);
	}
	fprintf(server_sock, "\n");
	return(1); // everything is ok 
}
*/

static char *
bittok2str_internal(const struct tok *lp, const char *fmt,
	   u_int v, const char *sep)
{
        static char buf[1024+1]; /* our string buffer */
        char *bufp = buf;
        size_t space_left = sizeof(buf), string_size;
        u_int rotbit; /* this is the bit we rotate through all bitpositions */
        u_int tokval;
        const char * sepstr = "";

	while (lp != NULL && lp->s != NULL) {
            tokval=lp->v;   /* load our first value */
            rotbit=1;
            while (rotbit != 0) {
                /*
                 * lets AND the rotating bit with our token value
                 * and see if we have got a match
                 */
		if (tokval == (v&rotbit)) {
                    /* ok we have found something */
                    if (space_left <= 1)
                        return (buf); /* only enough room left for NUL, if that */
                    string_size = strlcpy(bufp, sepstr, space_left);

                    if (string_size >= space_left)
                        return (buf);    /* we ran out of room */
                    bufp += string_size;
                    space_left -= string_size;
                    if (space_left <= 1)
                        return (buf); /* only enough room left for NUL, if that */
                    string_size = strlcpy(bufp, lp->s, space_left);

                    if (string_size >= space_left)
                        return (buf);    /* we ran out of room */
                    bufp += string_size;
                    space_left -= string_size;
                    sepstr = sep;
                    break;
                }
                rotbit=rotbit<<1; /* no match - lets shift and try again */
            }
            lp++;
	}

        if (bufp == buf)
            /* bummer - lets print the "unknown" message as advised in the fmt string if we got one */
            snprintf(buf, sizeof(buf), fmt == NULL ? "#%08x" : fmt, v);
        return (buf);
}

/*
 * Convert a bit token value to a string; use "fmt" if not found.
 * this is useful for parsing bitfields, the output strings are not seperated.
 */
char *
bittok2str_nosep(const struct tok *lp, const char *fmt,
	   u_int v)
{
    return (bittok2str_internal(lp, fmt, v, ""));
}

/*
 * Convert a bit token value to a string; use "fmt" if not found.
 * this is useful for parsing bitfields, the output strings are comma seperated.
 */
char *
bittok2str(const struct tok *lp, const char *fmt,
	   u_int v)
{
    return (bittok2str_internal(lp, fmt, v, ", "));
}

static int sock;
static struct sockaddr_in serveraddr;


void 
initsock(const char* host, int port)
{
  	sock = socket(AF_INET, SOCK_DGRAM, 0);
	
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_addr.s_addr = inet_addr(host);
	serveraddr.sin_port = htons(port);
/*
	if (connect(sock, (struct sockaddr *)&serveraddr, sizeof(serveraddr)) < 0)
	{
		perror("connect");
		exit(-1);
	}
*/

}

void writeToServer(const char * msg)
{	
    if (!msg[0]) return;
    sendto(sock, msg, strlen(msg), 0, (struct sockaddr *)&serveraddr, sizeof(struct sockaddr_in));
}

