module Blacklist; 

@if ( Cluster::is_enabled() )
@load base/frameworks/cluster
#redef Cluster::manager2worker_events += // ; 
redef Cluster::worker2manager_events += /Blacklist::aggregate_blacklist_stats/; 
@endif

function duration_to_hour_mins_secs(dur: interval): string
{

        if (dur < 0 sec)
                return fmt("%02d-%02d:%02d:%02d",0,0, 0, 0);

	local _secs = double_to_count(interval_to_double(dur)); 
	local _days = (_secs) / (60 * 60 * 24);
	_secs -= _days * (60 * 60 * 24);
	local _hours = _secs / (60 * 60);
	_secs -= _hours * (60 * 60);
	local _mins = _secs / 60;
	_secs -= _mins * (60);

        return fmt("%02d-%02d:%02d:%02d",_days, _hours, _mins, _secs );
}


event bro_init() &priority=5
{
        Log::create_stream(Blacklist::summary_LOG, [$columns=bl_stats_log]);
}

#@if ( ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || (!Cluster::is_enabled()))

function log_blacklist_summary(bs: bl_stats)
{

	#log_reporter(fmt ("LOGGER: %s", bs),0); 

	local info: bl_stats_log ;

	info$ts = network_time() ; 
	info$ls = bs$ls; 

	info$ipaddr = bs$ipaddr; 

	info$days_seen = |bs$days_seen|;
	info$first_seen = bs$first_seen ;
	info$last_seen = bs$last_seen ;

	info$active_for=duration_to_hour_mins_secs(info$last_seen-info$first_seen); 
	info$last_active=duration_to_hour_mins_secs(network_time() - info$last_seen); 
	local h_count = double_to_count(hll_cardinality_estimate(bs$hosts)); 
	info$hosts = h_count > 0 ? h_count : 1 ; 
	info$total_conns = bs$total_conns ; 
	info$source = blacklist_ip_table[bs$ipaddr]$source ; 

	Log::write(Blacklist::summary_LOG, info); 

	#log_reporter(fmt ("LOGGER: INFO: %s", info),0); 
} 
	
function Blacklist::report_manager_stats(t: table[addr] of bl_stats, idx: addr): interval 
{
	#log_reporter (fmt ("report_manager_stats: %s", t[idx]),0); 
	t[idx]$ls = ONGOING ; 
	log_blacklist_summary(t[idx]); 

	return LOGGING_TIME; 
} 
#@endif 


@if ( ( Cluster::is_enabled() && Cluster::local_node_type() != Cluster::MANAGER ) || (!Cluster::is_enabled()))
function expire_worker_stats(t: table[addr] of bl_stats, idx: addr): interval 
{
	#log_reporter (fmt ("expire_worker_stats: %s", idx),0); 

	event Blacklist::aggregate_blacklist_stats(t[idx]);
	
	return 0 secs; 
} 
@endif 

event new_connection(c: connection)
{
	local orig = c$id$orig_h ;
	local resp = c$id$resp_h ; 

	if (orig in Site::local_nets || orig in blacklist_removed )
		return ; 

	local seen = bloomfilter_lookup(blacklistbloom, orig);
	
	if (! seen ) 
		return ; 

	if (orig !in worker_stats)
	{
		local bs: bl_stats; 	
		worker_stats[orig]=bs ; 
		worker_stats[orig]$days_seen=vector(); 
		worker_stats[orig]$first_seen=c$start_time ; 
		worker_stats[orig]$days_seen[0]=c$start_time; 
	} 

	worker_stats[orig]$ts=network_time() ; 
	worker_stats[orig]$last_seen=c$start_time ; 
	worker_stats[orig]$total_conns += 1 ; 
	worker_stats[orig]$ipaddr = orig ; 
	hll_cardinality_add(worker_stats[orig]$hosts, resp); 
} 

@if ( ( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER ) || (!Cluster::is_enabled()))

function initialize_blacklist_summary(orig: addr, first_seen: time)
{

	#log_reporter(fmt("initialize_blacklist_summary: %s, %s", orig, first_seen),0); 

	if (orig !in manager_stats)
        {
                local b: bl_stats;
                manager_stats[orig]=b ;
                manager_stats[orig]$days_seen=vector();
                manager_stats[orig]$first_seen=first_seen;
                manager_stats[orig]$days_seen[0]=first_seen ;
        }

	
	manager_stats[orig]$first_seen  = first_seen ; 

        manager_stats[orig]$ts=network_time() ;
        manager_stats[orig]$last_seen=first_seen ; 
        manager_stats[orig]$total_conns += 1; 
        manager_stats[orig]$ipaddr = orig ;
		
	log_blacklist_summary(manager_stats[orig]);

} 

event Blacklist::aggregate_blacklist_stats(bs: bl_stats) 
{

	#log_reporter(fmt ("inside aggregate_blacklist_stats %s", bs),0); 

	local orig = bs$ipaddr; 

	### if an IP is removed from blacklist
	### we don't want to track its statistics anymore 
	if (orig in blacklist_removed)
		return ; 

	#if (orig !in manager_stats)
	#	initialize_blacklist_summary(orig, bs$first_seen);

	### update all the variables and aggregate based on what workers are returning 
	manager_stats[orig]$first_seen  = bs$first_seen < manager_stats[orig]$first_seen ? bs$first_seen : manager_stats[orig]$first_seen ; 

        manager_stats[orig]$ts=network_time() ;
        manager_stats[orig]$last_seen=bs$last_seen ; 
        manager_stats[orig]$total_conns += bs$total_conns ;
        manager_stats[orig]$ipaddr = orig ;
        manager_stats[orig]$ls = EPOCH ; 
        hll_cardinality_merge_into(manager_stats[orig]$hosts, bs$hosts );

        local n = |manager_stats[orig]$days_seen|;

        if (network_time() - manager_stats[orig]$days_seen[n-1] > SECS_ONE_DAY )
        {
                manager_stats[orig]$days_seen[|manager_stats[orig]$days_seen|] = bs$last_seen ;
		#log_blacklist_summary(manager_stats[orig]); 
        }
	
	#log_reporter(fmt ("inside aggregate_blacklist_stats II  %s", manager_stats[orig]),0); 
} 
@endif 
