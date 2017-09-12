module Scan;


#redef exit_only_after_terminate = T ; 

export {

	global PURGE_ON_WHITELIST = T ; 
        
	redef enum Notice::Type += {
		PurgeOnBlacklist, 
		BlacklistAdd, 
		BlacklistRemoved, 
		BlacklistChanged, 
	}; 

	const read_blacklist_timer: interval = 5 mins; 
	const update_blacklist_timer: interval = 5 mins; 

	const read_files: set[string] = {} &redef;

	global blacklist_ip_file:  string = "/YURT/feeds/BRO-feeds/blacklist.adhoc2" &redef ; 
	global blacklist_subnet_file:  string = "/YURT/feeds/BRO-feeds/blacklist.adhoc.subnet" &redef ; 

        type bl_ip_Idx: record {
                ip: addr;
        };

        type bl_ip_Val: record {
                ip: addr;
                comment: string &optional ;
        };
        
	type bl_subnet_Idx: record {
                nets: subnet ;
        };

        type bl_subnet_Val: record {
                nets: subnet ;
                comment: string &optional ;
	} ; 

        global blacklist_ip_table: table[addr] of bl_ip_Val = table() &redef ;
        global blacklist_subnet_table: table[subnet] of bl_subnet_Val = table() &redef ;

	type lineVals: record {
                d: string;
       	};

	const splitter: pattern = /\t/ ; 
	
	global Scan::m_w_add_ip: event(ip: addr, comment: string); 
	global Scan::m_w_update_ip: event(ip: addr, comment: string); 
	global Scan::m_w_remove_ip: event(ip: addr, comment: string); 
	
	global Scan::m_w_add_subnet: event(nets: subnet, comment: string); 
	global Scan::m_w_update_subnet: event(nets: subnet, comment: string); 
	global Scan::m_w_remove_subnet: event(nets: subnet, comment: string); 

}


@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
redef Cluster::manager2worker_events += /Scan::m_w_(add|update|remove)_(ip|subnet)/;
@endif

event reporter_error(t: time , msg: string , location: string )
{

	if (/blacklist.scan/ in msg)
	{ 
		print fmt ("bakwas error: %s, %s, %s", t, msg, location); 
		### generate a notice 
	} 
} 
	
event read_blacklist_ip(description: Input::TableDescription, tpe: Input::Event, left: bl_ip_Idx, right: bl_ip_Val)
{

	local _msg="" ; 
	local ip = right$ip ; 
	local comment= right$comment ; 
	local wl: bl_ip_Val; 

        if ( tpe == Input::EVENT_NEW ) 
	{
                #log_reporter(fmt (" scan-inputs.bro : NEW IP %s", ip), 0);
			
		blacklist_ip_table[ip]=wl ; 
		
		blacklist_ip_table[ip]$ip = ip; 
		blacklist_ip_table[ip]$comment= comment; 

		_msg = fmt("%s: %s", ip, comment);
                NOTICE([$note=BlacklistAdd, $src=ip, $msg=fmt("%s", _msg)]);

	@if ( Cluster::is_enabled() )
	        	event Scan::m_w_add_ip(ip, comment) ; 
	@endif	

        }
        
	if (tpe == Input::EVENT_CHANGED) {
                #log_reporter(fmt (" scan-inputs.bro : CHANGED IP %s, %s", ip, comment), 0);

		blacklist_ip_table[ip]$comment= comment; 

		_msg = fmt("%s: %s", ip, comment);
                NOTICE([$note=BlacklistChanged, $src=ip, $msg=fmt("%s", _msg)]);

	@if ( Cluster::is_enabled() )
	        	event Scan::m_w_update_ip(ip, comment) ; 
	@endif	
        }


        if (tpe == Input::EVENT_REMOVED ) {
                #log_reporter(fmt (" scan-inputs.bro : REMOVED IP %s", ip), 0);

		delete blacklist_ip_table[ip]; 

		_msg = fmt("%s: %s", ip, comment);
                NOTICE([$note=BlacklistRemoved, $src=ip, $msg=fmt("%s", _msg)]);

	@if ( Cluster::is_enabled() )
	        	event Scan::m_w_remove_ip(ip, comment) ; 
	@endif	
        }
	
	if ( ip !in blacklist_ip_table) 
	{
		blacklist_ip_table[ip]=wl ; 
	} 
		
	blacklist_ip_table[ip]$ip = ip; 
	blacklist_ip_table[ip]$comment= comment; 


}

event read_blacklist_subnet(description: Input::TableDescription, tpe: Input::Event, left: bl_subnet_Idx, right: bl_subnet_Val)
{
	local nets = right$nets; 
	local comment=right$comment ; 
	local _msg="" ; 

	#log_reporter(fmt (" SUBNETS: scan-inputs.bro : type %s", tpe), 0);

        if ( tpe == Input::EVENT_NEW ) {

                #log_reporter(fmt (" scan-inputs.bro : NEW Subnet %s", nets), 0);
		
		if (nets !in blacklist_subnet_table) 
		{
			local wl : bl_subnet_Val ; 
			blacklist_subnet_table[nets] = wl ; 
		} 

		blacklist_subnet_table[nets]$nets = nets; 
		blacklist_subnet_table[nets]$comment= comment; 

		_msg = fmt("%s: %s", nets, comment);
                NOTICE([$note=BlacklistAdd, $msg=fmt("%s", _msg)]);
		
	@if ( Cluster::is_enabled() )
	        	event Scan::m_w_add_subnet(nets, comment);
	@endif	
        }


        if (tpe == Input::EVENT_CHANGED) {
                #log_reporter(fmt (" scan-inputs.bro : CHANGED Subnet  %s, %s", nets, comment), 0);
		blacklist_subnet_table[nets]$comment= comment; 

		_msg = fmt("%s: %s", nets, comment);
                NOTICE([$note=BlacklistChanged, $msg=fmt("%s", _msg)]);
	
	@if ( Cluster::is_enabled() )
	        	event Scan::m_w_update_subnet(nets, comment);
	@endif	
        }

        if (tpe == Input::EVENT_REMOVED) {
                #log_reporter(fmt (" scan-inputs.bro : REMOVED Subnet  %s", nets),0 );
		delete blacklist_subnet_table[nets]; 

		_msg = fmt("%s: %s", nets, comment);
		NOTICE([$note=BlacklistRemoved, $msg=fmt("%s", _msg)]);

	@if ( Cluster::is_enabled() )
		event Scan::m_w_remove_subnet(nets, comment) ; 
	@endif	
        }


}

@if ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER )
event Scan::m_w_add_ip(ip: addr, comment: string)
        {

		local _msg="" ; 

        	log_reporter(fmt ("scan-inputs.bro: m_w_add_ip: %s, %s", ip, comment), 0);
		if ( ip !in blacklist_ip_table) 
		{
			local wl: bl_ip_Val; 
			blacklist_ip_table[ip]=wl ; 
		} 

		blacklist_ip_table[ip]$ip = ip; 
		blacklist_ip_table[ip]$comment= comment; 
	
		# disable for the time-being to keep consistency with changed, removed 
		# and webspiders are being logged already 

		_msg = fmt("%s: %s", ip, comment); 

		#NOTICE([$note=BlacklistAdd, $src=ip, $msg=fmt("%s", _msg)]);
		
		if (PURGE_ON_WHITELIST)
		{ 
			NOTICE([$note=PurgeOnBlacklist, $src=ip, $msg=fmt("%s", _msg)]);
			if (ip in known_scanners)
			{
				delete known_scanners[ip] ; 
			}

			_msg = fmt("%s is removed from known_scanners after blacklist: %s", ip, known_scanners[ip]); 

			@ifdef (NetControl::unblock_address_catch_release) 
				NetControl::unblock_address_catch_release(ip, _msg);
			@endif 
		}	 
	}

event Scan::m_w_update_ip(ip: addr, comment: string)
{
#log_reporter(fmt ("scan-inputs.bro: m_w_update_ip: %s, %s", ip, comment), 0);
blacklist_ip_table[ip]$comment= comment; 
}

event Scan::m_w_remove_ip(ip: addr, comment: string)
{
#log_reporter(fmt ("scan-inputs.bro: m_w_remove_ip: %s, %s", ip, comment), 0);
delete blacklist_ip_table[ip]; 
}


event Scan::m_w_add_subnet(nets: subnet, comment: string)
{
	#log_reporter(fmt ("scan-inputs.bro: m_w_add_subnet: %s, %s", nets, comment), 0);
	if (nets !in blacklist_subnet_table) 
	{
		local wl : bl_subnet_Val ; 
		blacklist_subnet_table[nets] = wl ; 
	} 

	blacklist_subnet_table[nets]$nets = nets; 
	blacklist_subnet_table[nets]$comment = comment;

	if (PURGE_ON_WHITELIST)
	{
		for (ip in known_scanners)
		{ 
			if (ip in nets)
			{

				local _msg = fmt("%s is removed from known_scanners after %s blacklist: %s", ip, nets, known_scanners[ip]);

				NOTICE([$note=PurgeOnBlacklist, $src=ip,
					$src_peer=get_local_event_peer(), $msg=fmt("%s", _msg)]);
				delete known_scanners[ip] ;

				@ifdef (NetControl::unblock_address_catch_release) 
					NetControl::unblock_address_catch_release(ip, _msg);
				@endif 
			} 
		} 
	}

} 

event Scan::m_w_update_subnet(nets: subnet, comment: string)
{
#log_reporter(fmt ("scan-inputs.bro: m_w_update_subnet: %s, %s", nets, comment), 0);
blacklist_subnet_table[nets]$comment = comment;
}

event Scan::m_w_remove_subnet(nets: subnet, comment: string)
{
#log_reporter(fmt ("scan-inputs.bro: m_w_remove_subnet: %s, %s", nets, comment), 0);
delete blacklist_subnet_table[nets]; 
}
@endif


event update_blacklist()
{
##log_reporter(fmt ("%s running update_blacklist", network_time()), 0);
#print fmt("%s", blacklist_ip_table); 

Input::force_update("blacklist_ip");
Input::force_update("blacklist_subnet");

schedule update_blacklist_timer  { update_blacklist() } ; 
}


event read_blacklist()
{
if ( ! Cluster::is_enabled() || Cluster::local_node_type() == Cluster::MANAGER )
	{
			Input::add_table([$source=blacklist_ip_file, $name="blacklist_ip", $idx=bl_ip_Idx, 
			$val=bl_ip_Val,  $destination=blacklist_ip_table, $mode=Input::REREAD,$ev=read_blacklist_ip]);

			Input::add_table([$source=blacklist_subnet_file, $name="blacklist_subnet", 
			$idx=bl_subnet_Idx, $val=bl_subnet_Val,  $destination=blacklist_subnet_table, 
			$mode=Input::REREAD,$ev=read_blacklist_subnet]);
	}

 #schedule update_blacklist_timer  { update_blacklist() } ; 
}


event bro_init() &priority=5
{
schedule read_blacklist_timer  { read_blacklist() }; 
}


event bro_done()
{
	for ( ip in blacklist_ip_table)
	{
		print fmt ("%s %s", ip , blacklist_ip_table[ip]); 
	} 
	for (nets in blacklist_subnet_table)
	{
		print fmt ("%s %s", nets, blacklist_subnet_table[nets]); 
	} 
}

