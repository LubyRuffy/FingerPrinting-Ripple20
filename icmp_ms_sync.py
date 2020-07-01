"""
Name: ICMP MS_SYNC Scanner
Description: This script tests if a host responds to ICMP MS_SYNC_REQ (ICMP type 165)
with ICMP MS_SYNC_RSP (ICMP type 166).
"""
from scapy.all import *

PASS_STR    = "PASS"
FAIL_STR    = "FAIL"
N_A_STR     = "N/A"

ICMP_MS_SYNC_REQ_TYPE = 0xa5
ICMP_MS_SYNC_RSP_TYPE = 0xa6

def keep_icmp_handler(func):
    def wrapper(*args, **kwargs):
        backup = ICMP.answers
        backup_err = ICMPerror.answers
        ICMP.answers = _icmp_answers
        ICMPerror.answers = _icmperror_answers
        res = func(*args, **kwargs)
        ICMP.answers = backup
        ICMPerror.answers = backup_err
        return res
    return wrapper

class Tester():
    
    name = "ICMP_MS_SYNC"

    def __init__(self, iface, timeout, port=None):
        self.iface = iface
        self.timeout = timeout

    @keep_icmp_handler
    def run(self, address):
        """
        Run the test.
        Should return True or False.
        """
        p = IP(dst=address)/ICMP(type=ICMP_MS_SYNC_REQ_TYPE)
        ans, unans = sr(p, iface=self.iface, timeout=self.timeout)

        if not ans:
            return N_A_STR
            
        for req, resp in ans:
            if ICMP in resp and resp[ICMP].type == ICMP_MS_SYNC_RSP_TYPE:
                return PASS_STR
        else:
            return FAIL_STR

def _icmp_answers(self, other):
    if not isinstance(other,ICMP):
        return 0
    if (self[ICMP].type == ICMP_MS_SYNC_RSP_TYPE and other[ICMP].type == ICMP_MS_SYNC_REQ_TYPE): # allow also destination unreachable + invalid protocol
        return 1
    return 0

def _icmperror_answers(self, other):
    if not isinstance(other, ICMP):
        return 0
    if bytes(self)[0] == 0xa5: # our special code
        return 1
    if not ((self.type == other.type) and
            (self.code == other.code)):
        return 0
    if self.code in [0, 8, 13, 14, 17, 18]:
        if (self.id == other.id and
                self.seq == other.seq):
            return 1
        else:
            return 0
    else:
        return 1