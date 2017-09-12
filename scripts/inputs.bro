module Blacklist;

#redef exit_only_after_terminate = T ; 

export {

	global blacklistbloom: opaque of bloomfilter ; 
	redef global_hash_seed = "blacklistbloomhash" ; 
        
	redef enum Notice::Type += {
		LocalNets, 
		Add, 
		AddSummary, 
		Removed, 
		Changed, 
		Stats, 
	}; 

	const update_blacklist_timer: interval = 60 mins; 
	const blacklist_stats_timer: interval = 3 mins; 

	const read_files: set[string] = {} &redef;

	global blacklist_ip_file:  string = fmt ("%s/feeds/blacklist.comment",@DIR) &redef ;  
	global blacklist_subnet_file:  string = fmt ("%s/feeds/blacklist.adhoc.subnet",@DIR)  &redef ; 
	global tor_bro24hrs_file:  string = fmt ("%s/feeds/CURRENT.24hrs_BRO", @DIR)  &redef ; 
	global cfm_fedmod_file:  string = fmt ("%s/feeds/CFM.7days_BRO", @DIR)  &redef ; 

        type bl_ip_Idx: record {
                ip: addr;
        };

        type bl_ip_Val: record {
                ip: addr;
                source: string &optional ;
                comment: string &optional ;
        };
        
	type bl_subnet_Idx: record {
                nets: subnet ;
        };

        type bl_subnet_Val: record {
                nets: subnet ;
                source: string &optional ;
                comment: string &optional ;
	} ; 

        global blacklist_ip_table: table[addr] of bl_ip_Val = table() &redef ;
        global blacklist_subnet_table: table[subnet] of bl_subnet_Val = table() &redef ;

	global blacklist_counter: count ; 

	global Blacklist::m_w_add_ip: event(val: bl_ip_Val); 
	global Blacklist::m_w_add_bloom: event(val: opaque of bloomfilter); 
	global Blacklist::m_w_add_table: event(val: set[addr]); 

	global Blacklist::m_w_update_ip: event(val: bl_ip_Val); 
	global Blacklist::m_w_remove_ip: event(val: bl_ip_Val);
	
	global Blacklist::m_w_add_subnet: event(nets: subnet, comment: string); 
	global Blacklist::m_w_update_subnet: event(nets: subnet, comment: string); 
	global Blacklist::m_w_remove_subnet: event(nets: subnet, comment: string); 

	global Blacklist::m_w_clear_blacklist_removed: event(ip: addr); 



	global already_nullzeroed: set[addr] &create_expire=1 day; 
	global blacklist_removed: set[addr] ; 
	global worker_peer_ids: table[count] of event_peer ; 

	global Blacklist::dump_blacklist_counts: event(); 
}
	
@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Blacklist::m_w_clear_blacklist_removed|Blacklist::m_w_(add|update|remove)_(ip|subnet|bloom|table)/;
@endif

event reporter_error(t: time , msg: string , location: string )
{

	if (/blacklist.adhoc/ in msg)
	{ 
		print fmt ("bakwas error: %s, %s, %s", t, msg, location); 
		### generate a notice 
	} 
} 


event Input::end_of_data(name: string, source:string)
{
	log_reporter(fmt("EVENT: Input::end_of_data: VARS name: %s", name),10);
	local n  = 0 ; 
	local _msg = "" ; 
	if ( name == "blacklist_ip")
	{

		n = |blacklist_ip_table| ; 
		_msg = fmt ("IPs Added = %s", n); 
		NOTICE([$note=AddSummary, $n=n, $msg=fmt("%s", _msg)]);	


		@if (Cluster::is_enabled() ) 
			event Blacklist::m_w_add_bloom(blacklistbloom); 
		@endif 
		#continue_processing(); 
	}
	if ( name == "blacklist_subnet")
	{
		n = |blacklist_subnet_table| ; 
		_msg = fmt ("Subnets Added = %s", n); 
		NOTICE([$note=AddSummary, $n=n, $msg=fmt("%s", _msg)]);	
	} 


}

event Blacklist::dump_blacklist_counts()
{
	local n = |blacklist_ip_table| ;
	local m = |blacklist_subnet_table| ;
	local o = |manager_stats| ;
	local p = |worker_stats| ;
    	local _msg = fmt ("IPs Added = %s, subnets Added= %s, manager_stats: %s, worker_stats: %s", n, m, o, p);
	NOTICE([$note=Stats, $n=n, $msg=fmt("%s", _msg)]);	

	schedule blacklist_stats_timer { Blacklist::dump_blacklist_counts() } ;
} 

#event Blacklist::read_ip(desc: Input::EventDescription, tpe: Input::Event, LV: Blacklist::bl_ip_Val)
event Blacklist::read_ip(description: Input::TableDescription, tpe: Input::Event, left: bl_ip_Idx, LV: bl_ip_Val)
{
	local _msg="" ; 
	local ip = LV$ip ; 
	local source = LV?$source ? LV$source : "" ; 
	local comment= LV$comment ; 

        if ( tpe == Input::EVENT_NEW ) 
	{

		if (ip in Site::local_nets)
		{
                	NOTICE([$note=LocalNets, $src=ip, $msg=fmt("%s", _msg)]);
			return ; 
		} 
		
		bloomfilter_add(blacklistbloom, ip); 

                #log_reporter(fmt (" blacklist-inputs.bro : NEW IP %s", ip), 40);
		#_msg = fmt("%s: %s", ip, comment);
                #NOTICE([$note=Add, $src=ip, $msg=fmt("%s", _msg)]);

		if (ip in blacklist_removed)
		{ 
			@if ( Cluster::is_enabled() )
				delete blacklist_removed[ip]; 
				event Blacklist::m_w_clear_blacklist_removed(ip); 
			@endif	
		} 
        }
        
	if (tpe == Input::EVENT_CHANGED) 
	{
                log_reporter(fmt (" blacklist-inputs.bro : CHANGED IP %s, %s", ip, comment), 0);

		_msg = fmt("%s: %s", ip, comment);
                NOTICE([$note=Changed, $src=ip, $msg=fmt("%s", _msg)]);

		@if ( Cluster::is_enabled() )
	        	event Blacklist::m_w_update_ip(LV);
		@endif	
   	}

        if (tpe == Input::EVENT_REMOVED ) 
	{
                log_reporter(fmt ("blacklist-inputs.bro : REMOVED IP %s", ip), 0);

		_msg = fmt("Removed the IP from Blacklist: %s: %s", ip, comment);
		NOTICE([$note=Removed, $src=ip, $msg=fmt("%s", _msg)]);

		add blacklist_removed[ip]; 

		if (ip in manager_stats)
		{ 
			manager_stats[ip]$ls=FINISH ; 
			log_blacklist_summary(manager_stats[ip]); 
			delete manager_stats[ip]; 

		} 

		@ifdef (NetControl::unblock_address_catch_release)
			NetControl::unblock_address_catch_release(ip, _msg);
		@endif
		
		@if ( Cluster::is_enabled() )
			event Blacklist::m_w_remove_ip(LV);
		@endif	
        }
}


#event Blacklist::read_subnet(desc: Input::EventDescription, tpe: Input::Event, LV: Blacklist::bl_subnet_Val)
event Blacklist::read_subnet(description: Input::TableDescription, tpe: Input::Event, left: bl_subnet_Idx, right: bl_subnet_Val)
{
	local nets = right$nets; 
	#local source = right$source ; 
	local comment=right$comment ; 
	local _msg="" ; 

	log_reporter(fmt (" SUBNETS: blacklist-inputs.bro : type %s", tpe), 0);

        if ( tpe == Input::EVENT_NEW ) {

                log_reporter(fmt (" blacklist-inputs.bro : NEW Subnet %s", nets), 0);

		_msg = fmt("%s: %s", nets, comment);
                NOTICE([$note=Add, $msg=fmt("%s", _msg)]);
		
		@if ( Cluster::is_enabled() )
	        	event Blacklist::m_w_add_subnet(nets, comment);
		@endif	
        }


        if (tpe == Input::EVENT_CHANGED) {
                #log_reporter(fmt (" blacklist-inputs.bro : CHANGED Subnet  %s, %s", nets, comment), 0);

		_msg = fmt("%s: %s", nets, comment);
                NOTICE([$note=Changed, $msg=fmt("%s", _msg)]);
	
		@if ( Cluster::is_enabled() )
	        	event Blacklist::m_w_update_subnet(nets, comment);
		@endif	
        }

        if (tpe == Input::EVENT_REMOVED) {
                #log_reporter(fmt (" blacklist-inputs.bro : REMOVED Subnet  %s", nets),0 );

		_msg = fmt("%s: %s", nets, comment);
		NOTICE([$note=Removed, $msg=fmt("%s", _msg)]);

		@if ( Cluster::is_enabled() )
			event Blacklist::m_w_remove_subnet(nets, comment) ; 
		@endif	
        }
}

#if (PURGE_ON_WHITELIST)
#{ 
#	NOTICE([$note=PurgeOnWhitelist, $src=ip, $msg=fmt("%s", _msg)]);
#
#	@ifdef (NetControl::unblock_address_catch_release) 
#		NetControl::unblock_address_catch_release(ip, _msg);
#	@endif 
#}	 

@if (( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || !Cluster::is_enabled()) 

event Blacklist::m_w_add_bloom(val: opaque of bloomfilter)
{
	log_reporter(fmt("calling inside the m_w_add_bloom"),0); 
	blacklistbloom=bloomfilter_merge(val, val);
} 

event Blacklist::m_w_add_table(val: set[addr])
{
	log_reporter(fmt("calling inside the m_w_add_table size: %s", |val|),0); 

	for (ip in val)
	{ 
		local l: bl_ip_Val ; 
		blacklist_ip_table[ip]=l;	
		blacklist_ip_table[ip]$ip=ip;
		blacklist_ip_table[ip]$source=""; 
		blacklist_ip_table[ip]$comment="";
	} 
} 


event Blacklist::m_w_add_ip(val: bl_ip_Val) 
        {

		local _msg="" ; 
		 local ip = val$ip ;
		local source = val$source ;
		local comment= val$comment ;

        	#log_reporter(fmt ("blacklist-inputs.bro: m_w_add_ip: %s, %s", ip, comment), 0);
		if ( ip !in blacklist_ip_table) 
		{
			local wl: bl_ip_Val; 
			blacklist_ip_table[ip]=wl ; 
		} 

		blacklist_ip_table[ip]$ip = ip; 
		blacklist_ip_table[ip]$comment= comment; 
	
		#_msg = fmt ("%s added to blacklist [%s]", ip, comment); 	
		#NOTICE([$note=Add, $src=ip, $msg=fmt("%s", _msg)]);
	}

event Blacklist::m_w_update_ip(val: bl_ip_Val)
{

	log_reporter(fmt("Blacklist::m_w_update_ip: %s", val),0); 

	local ip = val$ip ;
        local source = val$source ;
        local comment= val$comment ;

	#log_reporter(fmt ("blacklist-inputs.bro: m_w_update_ip: %s, %s", ip, comment), 0);
	blacklist_ip_table[ip]$comment= comment; 
}

event Blacklist::m_w_remove_ip(val: bl_ip_Val)
{
	local ip = val$ip ;
        local source = val$source ;
        local comment= val$comment ;

	log_reporter(fmt ("blacklist-inputs.bro: m_w_remove_ip: %s, %s", ip, comment), 0);
	add blacklist_removed[ip]; 
}

event Blacklist::m_w_clear_blacklist_removed(ip: addr)
{
	log_reporter(fmt("deleting ip from blacklist_removed: %s", ip), 0); 
	delete blacklist_removed[ip];
} 

event Blacklist::m_w_add_subnet(nets: subnet, comment: string)
{
	#log_reporter(fmt ("blacklist-inputs.bro: m_w_add_subnet: %s, %s", nets, comment), 0);
	if (nets !in blacklist_subnet_table) 
	{
		local wl : bl_subnet_Val ; 
		blacklist_subnet_table[nets] = wl ; 
	} 

	blacklist_subnet_table[nets]$nets = nets; 
	blacklist_subnet_table[nets]$comment = comment;

} 

event Blacklist::m_w_update_subnet(nets: subnet, comment: string)
{
	#log_reporter(fmt ("blacklist-inputs.bro: m_w_update_subnet: %s, %s", nets, comment), 0);
	blacklist_subnet_table[nets]$comment = comment;
}

event Blacklist::m_w_remove_subnet(nets: subnet, comment: string)
{
	#log_reporter(fmt ("blacklist-inputs.bro: m_w_remove_subnet: %s, %s", nets, comment), 0);
	delete blacklist_subnet_table[nets]; 
}

@endif


event update_blacklist()
{
	#log_reporter(fmt ("%s running update_blacklist", network_time()), 0);
	#print fmt("%s", blacklist_ip_table); 

	Input::force_update("blacklist_ip");
	Input::force_update("blacklist_subnet");

	schedule update_blacklist_timer { update_blacklist() } ; 
}


event read_blacklist()
{
	if ( ! Cluster::is_enabled() ||  Cluster::local_node_type() == Cluster::MANAGER )
	{

		Input::add_table([$source=blacklist_ip_file, $name="blacklist_ip", $idx=bl_ip_Idx,
               		$val=bl_ip_Val,  $destination=blacklist_ip_table, $mode=Input::REREAD,$ev=read_ip]);
		
		Input::add_table([$source=tor_bro24hrs_file, $name="blacklist_tor", $idx=bl_ip_Idx,
               		$val=bl_ip_Val,  $destination=blacklist_ip_table, $mode=Input::REREAD,$ev=read_ip]);
		
		Input::add_table([$source=cfm_fedmod_file, $name="blacklist_cfm", $idx=bl_ip_Idx,
               		$val=bl_ip_Val,  $destination=blacklist_ip_table, $mode=Input::REREAD,$ev=read_ip]);

		Input::add_table([$source=blacklist_subnet_file, $name="blacklist_subnet",
                       	$idx=bl_subnet_Idx, $val=bl_subnet_Val,  $destination=blacklist_subnet_table,
                       	$mode=Input::REREAD,$ev=read_subnet]);


		#Input::add_event([$source=blacklist_ip_file, $reader=Input::READER_ASCII, $mode=Input::REREAD, 
		#			$name="blacklist_ip", $fields=bl_ip_Val, $ev=read_ip]);
		
		#Input::add_event([$source=blacklist_subnet_file, $reader=Input::READER_ASCII, $mode=Input::REREAD, 
		#			$name="blacklist_subnet", $fields=bl_subnet_Val, $ev=read_subnet]);
	}
	 
	#schedule update_blacklist_timer  { update_blacklist() } ; 
	schedule blacklist_stats_timer { Blacklist::dump_blacklist_counts() } ;

}

event bro_init()
{
	#suspend_processing();

	blacklistbloom = bloomfilter_basic_init(0.001, 5000000); 
	schedule blacklist_stats_timer { Blacklist::dump_blacklist_counts() } ;
} 

@if ( ! Cluster::is_enabled()) 
event bro_init() &priority=5
{
	schedule 0sec { read_blacklist() };
}
@endif

@if ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )
global needed_node_count: count = 0;
event bro_init() &priority=5
	{
	for ( i in Cluster::nodes )
		{
		log_reporter(fmt("Cluster::nodes : %s, %s", i, Cluster::nodes[i]),0); 

		if ( Cluster::nodes[i]$node_type == Cluster::WORKER)
			needed_node_count+=1;
		}
	}
event remote_connection_handshake_done(p: event_peer)
	{


	if ( Cluster::nodes[p$descr]$node_type == Cluster::WORKER ) 
	{
		worker_peer_ids[p$id]=p ; 
		log_reporter(fmt("PEER is %s", worker_peer_ids[p$id]),0); 
	} 
	if ( Cluster::worker_count == needed_node_count )
		event read_blacklist();
	}
@endif

event bro_done()
{
	return ; 

	for ( ip in blacklist_ip_table)
	{
		print fmt ("%s %s", ip , blacklist_ip_table[ip]); 
	} 
	for (nets in blacklist_subnet_table)
	{
		print fmt ("%s %s", nets, blacklist_subnet_table[nets]); 
	} 
}



event NetControl::rule_exists(r: NetControl::Rule, p: NetControl::PluginState, msg: string)
{
        local ip = subnet_to_addr(r$entity$ip) ;

        if (ip in blacklist_ip_table && /is already nullzero routed/ in msg)
        {
		add already_nullzeroed[ip]; 
	} 

} 
