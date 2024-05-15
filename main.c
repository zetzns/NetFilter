#include <memory.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <net/route.h>
#include <linux/rtnetlink.h>
#include <unistd.h>
#include <libnetfilter_queue/libnetfilter_queue.h>
#include <libnetfilter_queue/pktbuff.h>
#include <libnetfilter_queue/libnetfilter_queue_ipv4.h>
#include <libnetfilter_queue/libnetfilter_queue_tcp.h>
#include <linux/netfilter.h>

#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

typedef char IPV4_ADDR[INET_ADDRSTRLEN];
typedef char IPV6_ADDR[INET6_ADDRSTRLEN];

#define NFQ_TRUE  1
#define NFQ_FALSE 0

unsigned char g_brepeat = NFQ_TRUE;

void signalHandler(int n_signum)
{
    printf("Handled Signal %d ...\n", n_signum);
    g_brepeat = NFQ_FALSE;
    return;
}

static int nfq_callbackfunc(struct nfq_q_handle *p_qhandle,
                            struct nfgenmsg     *p_nfqmsg,
                            struct nfq_data     *p_nfqarg,
                            void                *p_vdata)
{
    //int i_verdict = NF_ACCEPT;
    int i_verdict = NF_DROP;
    int i_pktid   = -1;

    char* p_pktbuffer = NULL;
    int n_pktlen = 0;
    
    do
    {
        if((NULL == p_qhandle )|| (NULL == p_nfqmsg) || (NULL == p_nfqarg))
        {
            break;
        }
        struct nfqnl_msg_packet_hdr*  p_pkthdr = nfq_get_msg_packet_hdr(p_nfqarg);
        if ( NULL != p_pkthdr)
        {
            i_pktid = ntohl(p_pkthdr->packet_id);
        }
        
        n_pktlen = nfq_get_payload (p_nfqarg, (unsigned char**)&p_pktbuffer);
        struct iphdr * ip_info = (struct iphdr *)p_pktbuffer;
        struct tcphdr * tcp_info = (struct tcphdr*)(p_pktbuffer + sizeof(*ip_info));

        if(n_pktlen > 0)
        {
            IPV4_ADDR c_srcaddr = {0};
            IPV4_ADDR c_dstaddr = {0};
            uint32_t  ui_ipaddr = 0;

            ui_ipaddr = *((uint32_t *) (p_pktbuffer + 12));
            inet_ntop(AF_INET, &ui_ipaddr, c_srcaddr, sizeof(c_srcaddr));

            ui_ipaddr = *((uint32_t *) (p_pktbuffer + 16));
            inet_ntop(AF_INET, &ui_ipaddr, c_dstaddr, sizeof(c_dstaddr));
            
            if (strcmp(c_srcaddr, "192.168.0.12") == 0) 
            {
                //printf("ACCEPT src PKT --> src_addr: %s to dst_addr: %s\n", c_srcaddr, c_dstaddr);
                
                if(ip_info->protocol == IPPROTO_TCP) //IPPROTO_UDP
                {                    
                    unsigned short dest_port = ntohs(tcp_info->dest);
                    unsigned short src_port = ntohs(tcp_info->source);
                    if(dest_port == 3306) 
                    {
                        printf("PORT source: %d dest: %d\n", src_port, dest_port);
                        //return nfq_set_verdict(p_qhandle, i_pktid, i_verdict, n_pktlen, p_pktbuffer);
                    }
                }
                return nfq_set_verdict(p_qhandle, i_pktid, NF_ACCEPT, n_pktlen, p_pktbuffer);
            }
            else
            {
       //         printf("Drop dest PKT --> src_addr: %s to dst_addr: %s\n", c_srcaddr, c_dstaddr);
                return nfq_set_verdict(p_qhandle, i_pktid, i_verdict, n_pktlen, p_pktbuffer);
            }
            
            printf("Received PKT --> src_addr: %s to dst_addr: %s\n", c_srcaddr, c_dstaddr);
        }
    }
    while(0);
    return nfq_set_verdict(p_qhandle, i_pktid, i_verdict, n_pktlen, p_pktbuffer);
}

static int _initializenetfilterqueue(void)
{
    int i_ret = NFQ_TRUE;

    /* Add The IP Table Rule */
    IPV4_ADDR c_srcaddr = "192.168.0.55";
    IPV4_ADDR c_subnetmask = "255.255.255.0";
    char c_intfname[IFNAMSIZ] = "eth0";

    IPV4_ADDR c_addr = {0};
    int n_subnet = 0;
    uint32_t  ui_ipaddr = inet_addr(c_srcaddr);
    uint32_t  ui_subnet = inet_addr(c_subnetmask);

    while (ui_subnet)
    {
      ui_subnet &= (ui_subnet-1) ;
      n_subnet++;
    }
    ui_subnet = inet_addr(c_subnetmask);

    ui_ipaddr = htonl(ui_ipaddr);
    ui_subnet = htonl(ui_subnet);

    ui_ipaddr = ui_ipaddr & ui_subnet;
    ui_ipaddr = htonl(ui_ipaddr);
    inet_ntop(AF_INET, &ui_ipaddr, c_addr, sizeof(c_addr));

    {
        char c_buffer[256] = "";
        sprintf (c_buffer, "/sbin/iptables -A FORWARD -i %s -j NFQUEUE --queue-num %d  -s %s/%d", c_intfname, getpid(), c_srcaddr, n_subnet);

        FILE* p_popen = NULL;
        p_popen = popen (c_buffer, "r");
        pclose(p_popen);
    }

    {
        char c_buffer[256] = "";
        sprintf (c_buffer, "/sbin/iptables -A INPUT -i %s -j NFQUEUE --queue-num %d  -s %s/%d", c_intfname, getpid(), c_srcaddr, n_subnet);

        FILE* p_popen = NULL;
        p_popen = popen (c_buffer, "r");
        pclose(p_popen);
    }

    return i_ret;
}

static int _finalizenetfilterqueue(void)
{
    int i_ret = NFQ_TRUE;
    {
        char c_buffer[256] = "";
        sprintf (c_buffer, "/sbin/iptables -F");

        FILE* p_popen = NULL;
        p_popen = popen (c_buffer, "r");
        pclose(p_popen);
    }

    return i_ret;
}

void* nfq_thread(void* pvArg)
{
    do
    {
        int i_status = 0;
        struct nfq_q_handle* p_snfqqhandle;

        if(_initializenetfilterqueue() != NFQ_TRUE)
        {
            printf("failed adding initializing iptable rule(s)\n");
            break;
        }

        int i_queuenum = getpid();

        struct nfq_handle* p_snfqhandle = nfq_open();
        if(p_snfqhandle == NULL)
        {
            printf("nfq_open failed with error code(%d) \n", errno);
            break;
        }

        i_status = nfq_unbind_pf(p_snfqhandle, AF_INET);
        i_status = nfq_bind_pf(p_snfqhandle, AF_INET);
        if(i_status < 0)
        {
            printf("nfq_bind_pf failed with error code(%d) \n", i_status);
            break;
        }

        p_snfqqhandle = nfq_create_queue(p_snfqhandle, i_queuenum , &nfq_callbackfunc, NULL);
        if(NULL == p_snfqqhandle)
        {
            printf("nfq_open failed with error code(%d) \n", errno);
            nfq_close(p_snfqhandle);
            break;
        }

        i_status = nfq_set_mode(p_snfqqhandle, NFQNL_COPY_PACKET, 0xffff);
        if (i_status < 0)
        {
            printf("nfq_set_mode failed with error code(%d) \n", errno);
            nfq_close(p_snfqhandle);
            break;
        }

        int n_fd = nfq_fd(p_snfqhandle);
#if 0
        struct nfnl_handle *p_nfqnlhandle =  nfq_nfnlh(p_snfqhandle);
        int n_fd = nfnl_fd(netlinkHandle);
#endif
        int n_maxfd = n_fd + 1;
        char c_buffer[10*1024] __attribute__ ((aligned)) = "";

        while(g_brepeat == NFQ_TRUE)
        {
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
            pthread_testcancel();
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);

            struct timeval o_timeout = {0 ,10000};
            fd_set o_readfdset;
            int i_numreadyfd = 0;

            FD_ZERO(&o_readfdset);
            FD_SET(n_fd,&o_readfdset);

            o_timeout.tv_sec =  0;
            o_timeout.tv_usec = 10000;

            i_numreadyfd = select( n_maxfd, &o_readfdset, NULL, NULL, &o_timeout);
            if(i_numreadyfd > 0)
            {
                int i_recvlen = recv(n_fd, c_buffer, sizeof(c_buffer), 0);
                if( i_recvlen >= 0)
                {
                    nfq_handle_packet(p_snfqhandle, c_buffer, i_recvlen);
                }
            }
        }

        if(NULL != p_snfqqhandle)
        {
            nfq_destroy_queue(p_snfqqhandle);
            p_snfqqhandle = NULL;
        }
        if(NULL != p_snfqhandle)
        {
            nfq_close(p_snfqhandle);
            p_snfqhandle = NULL;
        }

        _finalizenetfilterqueue();
    }
    while(0);
    pthread_exit(NULL);
}

int main()
{
    signal(SIGINT, signalHandler);
    do
    {
        pthread_t s_nfqthreadid;
        if (pthread_create (&s_nfqthreadid, NULL, nfq_thread, NULL) != 0)
        {
            printf("netfilter_thread Creation Failed ...\n");
            pthread_exit(NULL);
        }
        pthread_join(s_nfqthreadid, NULL);
    }
    while(0);
    return 0;
}
