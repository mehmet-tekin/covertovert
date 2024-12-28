import time
import random
import string
from scapy.all import (
    sniff, IP, UDP, DNS, DNSQR, ARP, LLC
)

from CovertChannelBase import CovertChannelBase

class MyCovertChannel(CovertChannelBase):
    """
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
    """

    def __init__(self):
        super().__init__()
        # Nibbles that indicates "stop" (0010 1110)
        self.stop_nibble1 = "0010"
        self.stop_nibble2 = "1110"

        # Receiving state variables
        self.received_bits = ""
        self.receiving_active = True
        self.stopfirstnibble = False
        self._current_in_count = 0

        self.reverse_dict = {}

    def send(self, log_file_name, parameter1, parameter2):
        
        # Generate a random binary message
        binary_message = self.generate_random_binary_message_with_logging(
            log_file_name=log_file_name,
            min_length=10,  # arbitrary
            max_length=30
        )

        # Split message into 4-bits
        nibbles = self.splitIntoNibbles(binary_message)

        # Sending nibbles
        for nib in nibbles[:-2]:
            self.sendNibble(nib, parameter2)

        # Send stop nibbles
        self.sendNibble(self.stop_nibble1, parameter2)
        self.sendNibble(self.stop_nibble2, parameter2)

    def receive(self, parameter1, parameter2, parameter3, log_file_name):

        self.received_bits = ""
        self.receiving_active = True
        self._current_in_count = 0

        # Build reverse dict
        self.reverse_dict = {val: key for key, val in parameter2.items()}

        # Sniffing
        sniff(
            filter="udp port 53",
            prn=self.packetHandler,
            stop_filter=self.stopFilter
        )

        decoded = self.bitsToASCII(self.received_bits)
        self.log_message(decoded, log_file_name)

    def sendNibble(self, nibble, mapping):
        count_in = mapping.get(nibble, 1)
        # Send count_in DNS queries (IN)
        self.sendInPackets(count_in)
        # Send CH
        self.sendCHDelimiter()

    def splitIntoNibbles(self, binary_str):
        
        return [binary_str[i:i+4] for i in range(0, len(binary_str), 4)]

    def sendInPackets(self, count_in):

        # Sends 'count_in' amount of DNS (IN) queries
        for _ in range(count_in):
            pkt = IP(dst="172.18.0.3") / UDP(dport=53) / DNS(
                rd=1,
                qd=DNSQR(qname="odtu.com", qtype="A", qclass=1)
            )
            CovertChannelBase.send(self, pkt, interface="eth0")
            self.sleep_random_time_ms(1, 3)

    def sendCHDelimiter(self):
        
        # Sends a single (CH) DNS query
        pkt = IP(dst="172.18.0.3") / UDP(dport=53) / DNS(
            rd=1,
            qd=DNSQR(qname="odtu.com", qtype="A", qclass=3)
        )
        CovertChannelBase.send(self, pkt, interface="eth0")
        self.sleep_random_time_ms(1, 3)

    def packetHandler(self, pkt):

        if not pkt.haslayer(DNS) or not pkt.haslayer(DNSQR):
            return

        dnsqr = pkt[DNSQR]
        if dnsqr.qclass == 1:
            # IN increase counter of cur nibble
            self._current_in_count += 1
            
        elif dnsqr.qclass == 3:
            # CH decode cur nibble
            self.decodeINCount()

    def decodeINCount(self):
        nibble = self.reverse_dict.get(self._current_in_count, None)
        self._current_in_count = 0

        if nibble is None:
            return
        # First Stop nibble
        if nibble == self.stop_nibble1:
            self.stopfirstnibble = True
            self.received_bits += nibble
        # Second Stop nibble
        elif nibble == self.stop_nibble2 and self.stopfirstnibble:
            self.stopfirstnibble = False
            self.receiving_active = False
            self.received_bits += nibble
        # Normal nibble
        else:
            self.stopfirstnibble = False
            self.received_bits += nibble

    def stopFilter(self, pkt):
        # Stop sniffing with receiving_active state
        return not self.receiving_active

    def bitsToASCII(self, bit_str):
        msg = ""
        for i in range(0, len(bit_str), 8):
            byte_str = bit_str[i:i+8]
            msg += self.convert_eight_bits_to_character(byte_str)
        return msg