Instructions for compliling and running my raw socket code

Compliling:
1. Run the following command
	gcc main.c -o raw_socket.bin

Running:
1. Start mininet
	mn
2. Get the mac address of h2
	h2 ifconfig -a
3. (Optional) Start wireshark for monitoring packets
	h2 wireshark &
4. Start a terminal for the receiver
	h2 xterm
5. Run the receiver
	./raw_socket.bin Recv h2-eth0
6. Start a terminal for the Sender
	h1 xterm
7. Run the sender
	./raw_socket.bin Send h1-eth0 <h2 MAC addr> '<your message>'


It was not explictly reqiured but I made my receiver ignore messages sent to MACs other than it's MAC address. Try it with an incorrect MAC address. 
