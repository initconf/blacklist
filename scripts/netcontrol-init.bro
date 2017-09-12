@load base/protocols/conn
@load base/frameworks/netcontrol

#redef exit_only_after_terminate = T; 

const broker_port: port = 9999/tcp &redef;

event bro_init()
{
}

event NetControl::init()
	{
	local pacf_acld = NetControl::create_acld([$acld_host=127.0.0.1, $acld_port=broker_port, $acld_topic="bro/event/pacf"]);
	NetControl::activate(pacf_acld, 0);
	}

event NetControl::init_done()
	{
	local ip = 1.1.1.1 ;
	
	local res = NetControl::drop_address(ip, 3 secs, "blah"); 

        local bi = NetControl::find_rules_addr(ip);

        #print fmt ("bi is : %s, result is : %s", bi, res);
	}

event BrokerComm::outgoing_connection_established(peer_address: string,
                                            peer_port: port,
                                            peer_name: string)
	{
	#print "BrokerComm::outgoing_connection_established", peer_address, peer_port;
	}

event NetControl::rule_added(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	# now that IP is nullzeroe'd
	local orig = subnet_to_addr(r$entity$ip) ;	
	if (orig in Blacklist::blacklist_ip_table)
	{ 
		add Blacklist::already_nullzeroed[orig];
		#print "Rule added successfully", r$id, msg;
	} 
	}

event NetControl::rule_error(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
	{
	#print "Rule error", r$id, msg;
	}

event NetControl::rule_timeout(r: NetControl::Rule, i: NetControl::FlowInfo, p: NetControl::PluginState)
	{
	#print "Rule timeout", r$id, i;
	}


hook NetControl::acld_rule_policy(p: NetControl::PluginState, r: NetControl::Rule, ar: NetControl::AclRule)
        {
        # use nullzero instead of drop for address drops
        if ( r$ty == NetControl::DROP && r$entity$ty == NetControl::ADDRESS && ar$command == "drop" && ! Site::is_local_addr(subnet_to_addr(r$entity$ip)) )
                ar$command = "nullzero";

	if (r$ty == NetControl::DROP && r$entity$ty == NetControl::ADDRESS && ar$command == "drop")
		ar$command = "nullzero"; 
	
        }

event NetControl::rule_exists(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
{
        local orig = subnet_to_addr(r$entity$ip) ;

	if (orig in Blacklist::blacklist_ip_table)
	{ 
		add Blacklist::already_nullzeroed[orig];
	} 

	#print fmt ("RULE Exists: %s, msg: %s", r, msg);
} 
