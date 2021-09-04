# ToDo

1. Build conntrack listener

* add code to main lua script that saves PID and forks off
* build formatter that extracts dst IP and mark
* design named pipe sender

2. Build named pipe startup code

* basically just create the named pipe with mkfifo

3. Build conntrack deletion function

* IP table for dst IP and timer
* ipset lookup code and function
* conntrack deletion code

4. Build service start code

* autostart on bootup and start() stop() restart() stats() functions

5. Build ipk

* we really want this to be easy to use. If we have configuration parameters that are user configurable we want to use the uci system in OpenWRT. We can port this stuff to other distros later.


