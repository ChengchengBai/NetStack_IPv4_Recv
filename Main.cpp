#include "Network_ipv4_recv.h"



pcap_t *handle;
extern char *device;
extern char error_buffer[PCAP_ERRBUF_SIZE];

int main()
{
	select_device();
	//device = pcap_lookupdev(error_buffer);

	handle = pcap_open_live(device, 65536, 1, 1000, error_buffer);

	pcap_loop(handle, NULL, ethernet_protocol_packet_callback, NULL);

	pcap_close(handle);
	return 0;
}