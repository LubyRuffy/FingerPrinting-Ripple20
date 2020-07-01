#Customized version of original code by TheSysOwner
 - Release: 07/01/2020
 - @TheSysOwner
# Treck Network Stack Discovery Tool by JSOF
- Version: 1.3
- Release: 06/22/2020

# Overview
This tool was developed in the JSOF security research labs. We appreciate any feedback and improvments. 
If you find any devices that run the Treck and are not on our list. We appreciate if notify us at ripple20@jsof-tech.com.

# Usage & Dependencies
The main file, `fingerprinting.py` should be executed with python 3. Add the `--help` option to see a detailed usage message: `python fingerprinting.py --help`.
Make sure all downloaded files are in the same directory, and that the following dependencies are installed: `scapy`, `tabulate`, `netaddr`. Missing dependencies can be installed using `pip`.

# Interpreting Results
After testing all IP addresses under the provided CIDR, a table with the results is displayed. 

For each test, the possible results are:
- `N/A`: The host didn't respond to the active test, so no verdict is made.
- `PASS`: Indicates that the host might use the Treck network stack.
- `FAIL`: Indicates that the host might NOT use the Treck network stack.
Currently, 3 different active tests are performed to detect Treck:
- **ICMP_MS_SYNC**: Sending ICMP with type `165 (0xa5)` to the target device results in an answer with ICMP type `166 (0xa6)`.
  - *HIGH RELIABILITY*. This is a unique behavior. However, failure cannot be verified to mean it isn't a Treck device. We have not seen any false positives to date. This can be used as a standalone signature.
- **IP TTL**: Initial IP TTL of echo reply messages is `255`; Initial IP TTL of other IP packets (e.g. TCP) is `64`.
  - *MEDIUM RELIABILITY*. Success cannot cannot be verified to mean it is a Treck device. Failure cannot be verified to mean it isn't a Treck device.
  - If ICMP `echo`s are disabled on your device or blocked by a firewall, this test will fail.
- **UNIQUE TCP**: Treck uses rather unique TCP window size and window scaling parameters in TCP connections.
  - *MEDIUM RELIABILITY*. If this test passes, it is a good indicator for Treck. However, there are variations within the Treck family, so failure doesn't mean it isn't a Treck device.
  - If no port number is specified, the following ports are checked: `443, 80, 21, 23, 22, 25, 465, 587, 161, 53`. At least one of them should be open and listening for TCP connections, otherwise, the test will fail.