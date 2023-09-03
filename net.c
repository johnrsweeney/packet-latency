#include <stdio.h>
#include <pcap.h>

int main(int argc, char *arv[]) {
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;
	const u_char *packet;

	dev = pcap_lookupdev(errbuf);
	if (dev == NULL) {
		fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
		return 2;
	}
	printf("Device: %s\n", dev);

	pcap_t *handle;
	handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		return 2;
	}

	fprintf(stdout, "pcap_datalink(handle): %d\n", pcap_datalink(handle));
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "Device %s doesn't provied Ethernet headers - not supported\n", dev);
		return 2;
	}

	/* Grab a Packet */
	packet = pcap_next(handle, &header);

	/* Print its length */
	printf("jacked a packet with length of [%d]\n", header.len);
	
	/* Close session */
	pcap_close(handle);
	
	return(0);
}
