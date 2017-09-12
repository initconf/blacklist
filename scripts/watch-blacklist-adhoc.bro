module Blacklist; 

export { 

	redef enum Notice::Type += {
		Drop, 
	} ; 

	global Blacklist::w_m_add_ip : event(cid: conn_id, ts: time); 
        global Blacklist::w_m_update_ip : event(cid: conn_id);
        global Blacklist::w_m_remove_ip : event(cid: conn_id); 

        global Blacklist::w_m_add_subnet : event(nets: subnet, comment: string);
        global Blacklist::w_m_update_subnet : event(nets: subnet, comment: string);
        global Blacklist::w_m_remove_subnet : event(nets: subnet, comment: string);

}

@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
#redef Cluster::worker2manager_events += /Blacklist::w_m_(add|update|remove)_(ip|subnet)/;
redef Cluster::worker2manager_events += /Blacklist::w_m_add_ip|Blacklist::w_m_update_ip|Blacklist::w_m_remove_ip/ ; 
@endif


@if ( ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || (!Cluster::is_enabled()))
event Blacklist::w_m_add_ip(cid: conn_id, start_time: time) 
{

	local ip = cid$orig_h ; 

	#log_reporter(fmt ("scan-inputs.bro: w_m_add_ip: %s",cid), 0);
	local _msg = fmt ("%s", Blacklist::blacklist_ip_table[ip]); 

	if (ip_drop_worthy())
	{ 
		local res = NetControl::drop_address_catch_release(ip, _msg); 
		_msg += fmt("Result: %s", res); 
		NOTICE([$note=Blacklist::Drop, $id=cid, $msg=_msg]);
		if (ip!in manager_stats)
                initialize_blacklist_summary(ip, start_time);
	} 
}

event Blacklist::w_m_update_ip(cid: conn_id)
{

	local ip = cid$orig_h ; 

	#log_reporter(fmt ("scan-inputs.bro: w_m_update_ip: %s", cid), 0);
}

event Blacklist::w_m_remove_ip(cid: conn_id)
{
	local ip = cid$orig_h ; 

	#log_reporter(fmt ("scan-inputs.bro: w_m_remove_ip: %s", cid), 0);

}

event Blacklist::w_m_add_subnet(nets: subnet, comment: string)
{
        #log_reporter(fmt ("scan-inputs.bro: w_m_add_subnet: %s, %s", nets, comment), 0);
}

event Blacklist::w_m_update_subnet(nets: subnet, comment: string)
{
	#log_reporter(fmt ("scan-inputs.bro: w_m_update_subnet: %s, %s", nets, comment), 0);
}

event Blacklist::w_m_remove_subnet(nets: subnet, comment: string)
{
	#log_reporter(fmt ("scan-inputs.bro: w_m_remove_subnet: %s, %s", nets, comment), 0);
}
@endif


######


function is_catch_release_active(cid: conn_id): bool
{
@ifdef (NetControl::BlockInfo)
        local orig = cid$orig_h ;

        local bi: NetControl::BlockInfo ;
        bi = NetControl::get_catch_release_info(orig);

        ### if record bi is initialized
        ### [block_until=<uninitialized>, watch_until=0.0, num_reblocked=0, current_interval=0, current_block_id=]
        ### 0.0 means empty bi
        if (bi$watch_until != 0.0 )
                return  T;

@endif

        return F ;
}

event new_connection(c: connection)
{
	#print fmt ("%s", c); 

	local orig = c$id$orig_h ;
	local resp = c$id$resp_h ; 

	if (orig in Site::local_nets)
		return ; 

	if (is_catch_release_active(c$id))
		return ; 

	if (orig in already_nullzeroed)
		return ; 

	local seen = bloomfilter_lookup(blacklistbloom, orig);
	if (seen > 0 && orig !in blacklist_removed)
	{
		#Log::write(Blacklist::LOG, [$ts=c$start_time, $uid=c$uid, $cid=c$id, $ipaddr=orig, $comment=""]);

		@if ( ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || (!Cluster::is_enabled()))
			#log_reporter(fmt("calling event Blacklist::w_m_add_ip: %s", orig),0); 
			event Blacklist::w_m_add_ip(c$id, c$start_time) ; 
			add already_nullzeroed[orig]; 
		@endif 
	} 
} 

### bi is : [[ty=NetControl::DROP, target=NetControl::FORWARD, entity=[ty=NetControl::ADDRESS, conn=<uninitialized>, flow=<uninitialized>, ip=1.1.1.1/32, mac=<uninitialized>], expire=3.0 secs, priority=0, location=blah, out_port=<uninitialized>, mod=<uninitialized>, id=2, cid=2, _plugin_ids={\x0a\x091\x0a}, _active_plugin_ids={\x0a\x0a}, _no_expire_plugins={\x0a\x0a}, _added=F]], result is : 2		

