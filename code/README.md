Our choosen covert channel implementation technique is Covert 
Storage Channel that exploits Protocol Field Manipulation using 
Answer Class field in DNS. In DNS there are 16 bits for DNS class
and the value of this field is generally 0x0001 for IN (Internet) and 0x0003
for CH (Chaosnet), which is used rarely for things like queryinig DNS
server versions. So it's a good candidate for covert channel. If we use 
CH channel too many times it will be suspicious, so we need to use it rather 
sparsly. Our method is to send data over covert channel, by counting the number of 
IN packets sent between two CH packets. We divide binaty representation into
nibbles (4 bits) and send each nibble by sending right amount of IN packets 
between two CH packets. We also send a stop nibbles (0010) and (1110) at the end of the
message. For receiving we sniff the DNS traffic and count the number of IN packets
between two CH packets to decode the nibble. We stop when we see the stop nibbles.
For adding additional security we also add a hash map as parameter for both send and 
receive. This hash map is used to map the nibble to the number of IN packets to send.
So the receiver gets the full data on the stop nibble tuple.

Alper Gülşen - 2380467
Mehmet Tekin - 2167328