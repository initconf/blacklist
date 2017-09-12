module Site;

export {

	global Site_NAMESERVERS: set[addr] =  { 1.1.1.1	#ns.example.com  
                                              } &redef ;

	global Site_MAILSERVERS: set[addr] = { 1.1.1.2	#mail.example.com 
					     } &redef ; 


	global watch_outgoing_ports: set[port] = { 53/tcp, 53/udp, 25/tcp, 587/tcp, 993/tcp } &redef ; 
} 
