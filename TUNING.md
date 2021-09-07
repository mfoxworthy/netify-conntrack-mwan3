# Tuning

I tested several options however, the single biggest factor is how long the entry remians in the set. We initially had the ttl set to 600. However, when my code detects an entry in the incorrect iplist I delete it and put it in the correct list. I use the -exist switch on the list add command to force the entry. I use it on the delete command to. It also suppresses errors if the entry is or isn't in the ipset list. 

# Time To Live settings

All this said, I turned off the ttl in Netify. This completely stablized the network. There is a growing list of entries in each of the lists. But, if an IP is used for an application meant for the other network, I still move it. So list growth isn't really a concern. However, if it becomes a concern we just need to make the ttl something really long like 48 hours. After testing for 24 hours the list, in my enviroment grew to

227 - Network with the fewest rules but has streaming media configured

424 - Network with all the buisness apps and interactive apps like chat.

# Interface detection

From time to time an interface may go offline in mwan3. When this happens the rules associated with that interface in netfilter go away. I need to work out the detection function to ride through that. The mark is on the packet but if the route isn't avaialbe I believe the flow will take the default. Adding the flow to the correct ipset list and resetting it should break anything.