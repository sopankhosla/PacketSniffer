#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>

struct ieee80211_radiotap_header {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
};

/*========defined but not used=========*/
/*prism value */
struct prism_value{
u_int32_t did;
u_int16_t status;
u_int16_t len;
u_int32_t data;
};

/*prism header for traditional wireless card*/
struct prism_header{
u_int32_t msgcode;
u_int32_t msglen;
struct prism_value hosttime;
struct prism_value mactime;
struct prism_value channel;
struct prism_value rssi;
struct prism_value sq;
struct prism_value signal;
struct prism_value noise;
struct prism_value rate;
struct prism_value istx;
struct prism_value frmlen;
};

void handlePacket(const u_char* packet, int len) {
	int i;
	
	//struct ieee80211_radiotap_header* rth = (struct ieee80211_radiotap_header*)(packet);
	//printf("rth len=%d\n", rth->it_len);
	//printf("packet len = %d\n", len);

	struct prism_header* rth1 = (struct prism_header*)(packet);
	// printf("rth len=%d\n", rth1->msglen);
	
	// skip
	i = rth1->msglen;		// this is radiotap header which is added before the actual frame
	
	int j = i;
	
    //for(; i<len; i++) {
    //	printf("%02X", packet[i]);
    // }
    
    // printf("\nFollowing fields are shown for each packet, but they may or may not be available in each frame.\n");
    
    i = j = rth1->msglen + 4;	// skip frame control + duration
    
    printf("Addr1: ");
    for(; (i < j + 6) && (i < len); i++) {
    	printf("%02X", packet[i]);
    }
    
    j = i;
    printf("  Addr2: ");
    for(; (i < j + 6) && (i < len); i++) {
    	printf("%02X", packet[i]);
    }
    
    j = i;
	printf("  Addr3: ");
    for(; (i < j + 6) && (i < len); i++) {
    	printf("%02X", packet[i]);
    }

    i++;
    i++;
    j = i;    
	printf("  Addr4: ");
    for(; (i < j + 6) && (i < len); i++) {
    	printf("%02X", packet[i]);
    }

    printf("\n");
}

/* callback function that is passed to pcap_loop(..) and called each time 
 * a packet is recieved                                                    */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char*
        packet)
{
    handlePacket(packet, pkthdr->len);
}

int main(int argc,char **argv)
{ 
    int i;
    char *dev; 
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    const u_char *packet;
    struct pcap_pkthdr hdr;     /* pcap.h */
    struct ether_header *eptr;  /* net/ethernet.h */

    if(argc != 3){ fprintf(stdout,"Usage: %s interface_name numpackets\n",argv[0]);return 0;}

    dev = argv[1];
    
    if(dev == NULL)
    { printf("%s\n",errbuf); exit(1); }
    /* open device for reading */

    descr = pcap_open_live(dev,BUFSIZ,1,-1,errbuf);
    printf("datalink: %d\n",pcap_datalink(descr));

    pcap_loop(descr,atoi(argv[2]),my_callback,NULL);

    fprintf(stdout,"\nDone!\n");
    return 0;

    /*
    descr = pcap_create(dev,errbuf);

    if(descr == NULL)
    { printf("pcap_open_live(): %s\n",errbuf); exit(1); }

    if(pcap_can_set_rfmon(descr)==0)
    {
	printf("Can not set the device in Monitor Mode: %s\n",errbuf); exit(1); 
    }	
    
    if(1)
    {
    int ret_val = pcap_set_rfmon(descr,1);
    printf(" return value : %d \n",ret_val); 
    if(ret_val==0)	
    {
	printf("Monitor Mode is on \n"); 
    }
    }
    
    
    int ret = pcap_set_snaplen(descr, 2048);  // Set the snapshot length to 2048

	if (ret < 0) printf("pcap_set_snaplen failed %s\n", pcap_geterr(descr));	

    ret = pcap_set_timeout(descr, -1);	

	if (ret < 0) printf("pcap_set_snaplen failed %s\n", pcap_geterr(descr));	


    ret = pcap_set_buffer_size(descr, 1000000); 

	if (ret < 0) printf("pcap_set_snaplen failed %s\n", pcap_geterr(descr));	

    ret = pcap_set_promisc(descr, 0);

	if (ret < 0) printf("pcap_set_snaplen failed %s\n", pcap_geterr(descr));	

    ret = pcap_activate(descr);

	if (ret < 0) printf("Activation error %s\n", pcap_geterr(descr));	

    */	


    
}