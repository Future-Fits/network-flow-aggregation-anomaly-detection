#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bcc/proto.h>


struct network_flow_data {
    u64 total_bytes_sent;
    u64 total_packets;
    u64 avg_payload_size;
    u64 max_payload_size;
    u64 min_payload_size;
};



BPF_HASH(flow_data, uint32_t, struct network_flow_data, 4096);

int packet_parser(struct __sk_buff *skb) {
    unsigned char *cursor = 0;
    unsigned int *port_ptr;

    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    if (ethernet->type != 0x0800) {
        return 0;
    }

    struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

    if (ip->nextp == 0x06) {
        struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));



        int payload_size = ip->tlen - 4*ip->hlen - 4*tcp->offset;

        struct network_flow_data zero = {0,0,0,0,0};

        unsigned int key = tcp->dst_port;
        struct network_flow_data *flow_data_ptr;
        flow_data_ptr = flow_data.lookup_or_try_init(&key, &zero);

        if(flow_data_ptr == 0){
            bpf_trace_printk("Not found");
            return 0;
        }

        flow_data_ptr->total_bytes_sent += payload_size;
        
        flow_data_ptr->avg_payload_size = (flow_data_ptr->avg_payload_size * flow_data_ptr->total_packets + payload_size)/(flow_data_ptr->total_packets+1);
        flow_data_ptr->total_packets++;


        if (payload_size > flow_data_ptr->max_payload_size) {
            flow_data_ptr->max_payload_size = payload_size;
        }

        if (payload_size < flow_data_ptr->min_payload_size || flow_data_ptr->min_payload_size == 0) {
            flow_data_ptr->min_payload_size = payload_size;
        }

    } else if (ip->nextp == 0x11) {
        struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));

        int payload_size = udp->length;

        struct network_flow_data zero = {0,0,0,0,0};

        unsigned int key = udp->dport;
        struct network_flow_data *flow_data_ptr;
        flow_data_ptr = flow_data.lookup_or_try_init(&key, &zero);

        if(flow_data_ptr == 0){
            bpf_trace_printk("Not found");
            return 0;
        }

        flow_data_ptr->total_bytes_sent += payload_size;
        
        flow_data_ptr->avg_payload_size = (flow_data_ptr->avg_payload_size * flow_data_ptr->total_packets + payload_size)/(flow_data_ptr->total_packets+1);
        flow_data_ptr->total_packets++;


        if (payload_size > flow_data_ptr->max_payload_size) {
            flow_data_ptr->max_payload_size = payload_size;
        }

        if (payload_size < flow_data_ptr->min_payload_size || flow_data_ptr->min_payload_size == 0) {
            flow_data_ptr->min_payload_size = payload_size;
        }

    }

    return 0;
}
