module Blacklist; 

export { 

	redef enum Log::ID += { adhoc } ; 	
	redef enum Log::ID += { LOG } ; 	

	#redef enum Notice::Type += {
	#} ; 

	type blacklist_log: record {
		ts: time ; 
		ipaddr: addr ; 
		days_seen: vector of time; 
		first_seen: time &log &optional  &default=double_to_time(0.0);
		last_seen: time &log &optional  &default=double_to_time(0.0);
		hosts_scanned: count &default=1;
		total_conns: count &default=1; 
		comment: string ; 
	} &log ; 	
}
	
function log_blacklist_adhoc(cid: conn_id): bool
{
	local orig = cid$orig_h ;
	local resp = cid$resp_h ; 

	if (orig in Site::local_nets)
		return F;

	if (orig in Blacklist::blacklist_ip_table) 
		return T ; 

	return F ; 
} 

event bro_init()
{

	if (CREATE_BLACKLIST_ADHOC_CONN_LOG)
	{ 
		Log::add_filter(Conn::LOG, [$name="blacklist-adhoc", 
			$path="blacklist-adhoc", 
			$pred(rec: Conn::Info) = { return log_blacklist_adhoc(rec$id); }]); 
	} 
}
