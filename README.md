# OSPF Parser
A simple OSPF Parser based on tcpdump. It will send analysis data to server.

## Usage
`ospf_handler -i <interface> -h <IP> -p <port>`
- `<interface>` Sniff OSPF packets on this interface
- `<IP>` Server IP
- `<port>` Server port

You need to set up a program that listening on the port you choose, such as `nc -l -p <port>`.

## Result
The program will send all of the parsed OSPF packet to the server's port(As we need, OSPF Hello will be filtered out). You can redirct the output stream to a file.
```bash
nc -l -p 8000 > result.txt
```
You may sort the result by timestamp.
```bash
cat result0.txt result1.txt result2.txt | sort -n -o merged_result.txt
```
