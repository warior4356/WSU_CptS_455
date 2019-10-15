Instructions for compliling and running my ARP code

Compliling:
1. Run the following command
	gcc main.c -o arp.bin

Running:
1. Start mininet
	mn
2. Get the ip address of h2
	h2 ifconfig -a
3. (Optional) Start wireshark for monitoring packets
	h2 wireshark &
4. Start a terminal for the receiver
	xterm h2
5. Run the receiver
	./arp.bin R_ARP h2-eth0
6. Start a terminal for the Sender
	xterm h2
7. Run the sender
	./arp.bin S_ARP h1-eth0 <h2 IP addr> 

HW1 functions still work
