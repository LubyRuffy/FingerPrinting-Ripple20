"""
Name: IP TTL Discrepancy Scanner
Description: Checks for discrepancies in the TTL between ICMP echo reply (255) and other packets (64).
"""
from scapy.all import *

PASS_STR    = "PASS"
FAIL_STR    = "FAIL"
N_A_STR     = "N/A"

ICMP_ECHO_REPLY_TYPE    = 0
EXPECTED_REGULAR_TTL    = 64
EXPECTED_ICMP_TTL       = 255
MAX_IP_HOPS             = 20

class Tester():

    name = "IP TTL"

    def __init__(self, iface, timeout, port=None):
        self.iface = iface
        self.timeout = timeout

    def run(self, address):
        """
        Run the test.
        Should return True or False.
        """
        # first, check the ttl on an echo reply
        p = IP(dst=address)/ICMP(type="echo-request")
        ans, unans = sr(p, iface=self.iface, timeout=self.timeout)
        
        if not ans:
            return N_A_STR

        for req, resp in ans:
            if ICMP in resp and resp[ICMP].type == ICMP_ECHO_REPLY_TYPE:
                icmp_echo_reply_ttl = resp["IP"].ttl
                break
        else:
            return FAIL_STR
        
        # check ttl distance
        ttl_distance = EXPECTED_ICMP_TTL - icmp_echo_reply_ttl

        # now get the TTL of another packet
        p = IP(dst=address)/TCP(sport=40509, dport=40508, flags="S")
        ans, unans = sr(p, iface=self.iface, timeout=self.timeout)
        
        if not ans:
            return N_A_STR

        for req, resp in ans:
            if IP in resp:
                tcp_rst_ttl = resp["IP"].ttl
                break
        else:
            return FAIL_STR

        # COMPARE!
        if tcp_rst_ttl + ttl_distance == EXPECTED_REGULAR_TTL and ttl_distance < MAX_IP_HOPS:
            return PASS_STR
        else:
            return FAIL_STR
