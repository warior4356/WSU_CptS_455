Instructions for compliling and running my UDP code

Compliling:
1. Run the following command
	gcc -o server.bin server_udp.c & gcc -o client.bin client_udp.c 

Running:
1. Start mininet and pox as the assignment, change the mininet port if needed with ,port=XXXX

2. Make two terminals with xterm h1 h2

3. Start the receiver ./server_udp output.txt

4. Send the message ./client_udp 10.0.0.2 tux.txt

5. Verify it with diff tux.txt output.txt
