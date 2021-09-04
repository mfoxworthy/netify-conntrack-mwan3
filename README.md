# netify-conntrack-mwan3
Netfilter conntrack reset function to solve misplaced flows after application detection

# Introduction

Netify and mwan3 are tools used in OpenWRT to provide an SD-WAN solution. Netify provides application detection and classification. mwan3 provides networking funtions such as link health detection, forwarding rules and classification. Together, a comprehensive SD-WAN solution with edge DPI functionality can be built. One drawback is that DPI sometimes takes several packets before an application can be identified. In these cases the connection could be made on the incorrect interface thus not creating the user experience desired.

# Proposed solution

This project is being developed to solve what is called the "first packet detecion" issue. In prelinary tests we've proven that deleting the connection in the netfilter connection tracking list will force TCP to send a reset flag to both sides of the NAT and UDP will just create a new tracking entry.

When a new flow is started, Netify listens on the wire and records the flow. Once the application has been identified, Netify adds an entry to the IPSET list for the configured rule. For example, we can have an IPSET set called app_1.v4. When a flow is started Netify will detect that app_1 is present and add the IP address of the flow to the IPSET rule. mwan3 is then configured to use a partular interface for all IPs in the app_1.v4 IPSET set. However, when the 3-way handshake occurs, Netify and mwan3 don't have all the neccesary information to determine the flow type. Therefore, the flow falls into the default rule. In some cases the default rule may be to load balance. This is where the issue arises. If we want app_1 to always use interface_1 when available we may only get what we want 50% of the time when two interfaces are in the load balance group. Even less if there are more interfaces. When this happens we want to correct it as soon as possible. 

We know a few things about the flow:

We know the flow was created by looking in the /proc/net/nf_conntrack file.
We know which interface the flow is on by looking at the mark on the entry found in nf_conntrack file.
We know, after detection, which connections belong on particular interfaces by looking at the IPSET list.

Comparing the mark with the IPSET list we can determnie which interface the flow was designated for. If the flow is on the wrong interface, we can do one of the following:

1. We can simply delete the entry in nf_filter. With TCP this will force a reset and with UDP packets will just start to flow again. This method is used once the IP address is in the IPSET list. This way the subsequent flow will use the correct interface
2. We can change the parameters of the flow by changing the source NAT IP in the conntrack. (This has not been tested)

There exists a Linux utility called conntrack. This tool can be used to manipulate the entries in the nf_conntrack file. 

"conntrack -L -d <ip address>" will list all the flows in the nf_conntrack file containing the given destination IP address.
"conntrack -D -d <ip address>" will delete all entries with the given destination IP address.
"ipset list <list name, i.e., app_1.v4>" will provide a list of IPS in the set.
  
The idea is to create a named pipe and pump new connection information into the pipe.

What I have done is used the "conntrack -E" command to provide a continuous event list with conntrack events.
  
  Example:
  "root@GL-X750:~# conntrack -E
[DESTROY] udp      17 src=192.168.88.62 dst=8.8.8.8 sport=52725 dport=53 packets=1 bytes=86 src=8.8.8.8 dst=192.168.88.62 sport=53 dport=52725 packets=1 bytes=134 mark=256
 [UPDATE] tcp      6 10 CLOSE src=192.168.88.62 dst=35.182.46.62 sport=42350 dport=443 src=35.182.46.62 dst=192.168.88.62 sport=443 dport=42350 [ASSURED] mark=256
    [NEW] tcp      6 120 SYN_SENT src=192.168.88.62 dst=35.182.46.62 sport=42352 dport=443 [UNREPLIED] src=35.182.46.62 dst=192.168.88.62 sport=443 dport=42352 mark=256
 [UPDATE] tcp      6 60 SYN_RECV src=192.168.88.62 dst=35.182.46.62 sport=42352 dport=443 src=35.182.46.62 dst=192.168.88.62 sport=443 dport=42352 mark=256
 [UPDATE] tcp      6 7440 ESTABLISHED src=192.168.88.62 dst=35.182.46.62 sport=42352 dport=443 src=35.182.46.62 dst=192.168.88.62 sport=443 dport=42352 [ASSURED] mark=256
    [NEW] icmp     1 30 src=10.70.136.192 dst=8.8.8.8 type=8 code=0 id=22664 [UNREPLIED] src=8.8.8.8 dst=10.70.136.192 type=0 code=0 id=22664 mark=512
[DESTROY] icmp     1 src=192.168.88.62 dst=8.8.4.4 type=8 code=0 id=21886 packets=1 bytes=84 src=8.8.4.4 dst=192.168.88.62 type=0 code=0 id=21886 packets=1 bytes=84 mark=256
 [UPDATE] icmp     1 30 src=10.70.136.192 dst=8.8.8.8 type=8 code=0 id=22664 src=8.8.8.8 dst=10.70.136.192 type=0 code=0 id=22664 mark=512
    [NEW] icmp     1 30 src=192.168.88.62 dst=8.8.4.4 type=8 code=0 id=22680 [UNREPLIED] src=8.8.4.4 dst=192.168.88.62 type=0 code=0 id=22680 mark=512
 [UPDATE] icmp     1 30 src=192.168.88.62 dst=8.8.4.4 type=8 code=0 id=22680 src=8.8.4.4 dst=192.168.88.62 type=0 code=0 id=22680 mark=512
[DESTROY] icmp     1 src=10.70.136.192 dst=8.8.8.8 type=8 code=0 id=21879 packets=1 bytes=84 src=8.8.8.8 dst=10.70.136.192 type=0 code=0 id=21879 packets=1 bytes=84 mark=256
    [NEW] udp      17 60 src=192.168.8.108 dst=91.189.91.157 sport=37818 dport=123 [UNREPLIED] src=91.189.91.157 dst=192.168.88.62 sport=123 dport=37818 mark=256
 [UPDATE] udp      17 60 src=192.168.8.108 dst=91.189.91.157 sport=37818 dport=123 src=91.189.91.157 dst=192.168.88.62 sport=123 dport=37818 mark=256
[DESTROY] udp      17 src=192.168.88.62 dst=8.8.4.4 sport=52725 dport=53 packets=1 bytes=86 src=8.8.4.4 dst=10.70.136.192 sport=53 dport=52725 packets=1 bytes=134 mark=512
[DESTROY] tcp      6 src=192.168.88.62 dst=35.182.46.62 sport=42348 dport=443 packets=19 bytes=5181 src=35.182.46.62 dst=192.168.88.62 sport=443 dport=42348 packets=17 bytes=5896 [ASSURED] mark=256
[DESTROY] udp      17 src=192.168.8.108 dst=192.168.8.1 sport=56989 dport=53 packets=1 bytes=86 src=192.168.8.1 dst=192.168.8.108 sport=53 dport=56989 packets=1 bytes=134 mark=16128
[DESTROY] udp      17 src=192.168.88.62 dst=172.26.38.1 sport=52725 dport=53 packets=1 bytes=86 [UNREPLIED] src=172.26.38.1 dst=192.168.88.62 sport=53 dport=52725 packets=0 bytes=0 mark=256
[DESTROY] icmp     1 src=192.168.88.62 dst=8.8.4.4 type=8 code=0 id=21996 packets=1 bytes=84 src=8.8.4.4 dst=192.168.88.62 type=0 code=0 id=21996 packets=1 bytes=84 mark=256
^Cconntrack v1.4.5 (conntrack-tools): 18 flow events have been shown."
  
All the entries with [NEW] flagged are what we are interested in. The entries with a dst containing a directly connected network we throw out. We record two items in each entry, the outbound dst IP, which is the first one in the entry and the mark at the end. We send these two items to the named pipe. We then build a listener on the named pipe that uses each new entry to run through a decision tree. First, we evaluate the mark to determine which interface this connection is established on. We then read our interface map var to determine which set the dst IP has been added to. It's worth mentioning that right now I am only using hash:ip sets. I am not using hash:ip:port sets. This being said, if we have back to back conntracks with the same IP we only need to process one of them. We should be setting a var with the previous IP and a timer. This will reduce the amount of ipset list commands we have to issue. The timer is useful in very quiet networks. For example, if we get two identical IPs but they are 10 minutes apart, it's likely the ipset entry has aged. So, when we look up the IP in the set we should also use the timeout value that is contained in the ipset to set our timer. I know, I know, "But what if we get two identical IPs, say, 3 or 4 apart?". That is anoptimization and if anyone wants to chime in on a data structure we can use that can speed things up, I'm all ears.
  
Now that we know the IP and interface, we look it up in IPSET. If the current interface doesn't map to the ipset set, we simply delete the connection. In the case of TCP, the RESET flag will be set and both sides will delete socket and perform a 3-way handshake. In the case of UDP a new conntrack will be established and NAT do it's thing. I haven't tested this with protocols like TFTP. Some help here would be welcome for sure.
  
# Implementation

My first version is written in Lua. I am using OpenWRT and I have limited resources. This should be the baseline anyway. We need this to be small and fast. Lua is a small language that fits nicely on OpenWRT platforms and gives us feature that ash shell doesn't provide. 
  
We need two functions with thier own fork and PID.
  
  1. The conntrack event function that watches new entries and formats the data before it is sent to the named pipe.
  2. The entry manager that listens to the named pipe and performs the delte function.
  
This does'nt need to be high speed. In fact we may actually want to sit a few seconds behind each new flow. When the new connection is added to the nf_conntrack file, it happens at the 3-way handshake. We may not have an IPSET set entry for a few packets. Maybe we build a short queue with a wait funtion? Maybe we sit on the ipset lists and match IP addresses as they are added? Thoughts?
  


