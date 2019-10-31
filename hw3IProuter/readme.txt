Instructions for compliling and running my router code

Compliling:
1. Run the following command
	gcc main.c -o router.bin

Running:
1. Start mininet with the script
	sudo ./router.py
2. Get the ip address of h3x2
	h3x2 ifconfig
3. Get the ip address of the router
	r0 ifconfig
3. (Optional) Start wireshark for monitoring packets
	h1x1 wireshark &
4. Start a terminal for the receiver
	xterm h3x2
5. Run the receiver
	./arp.bin Recv h3x2-eth0
6. Start a terminal for the Sender
	xterm h1x1
7. Run the sender
	./arp.bin Send h1-eth0 <h3x2 IP addr> <router IP addr> <message>
