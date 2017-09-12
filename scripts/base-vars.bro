module Blacklist ;
	

#redef exit_only_after_terminate = T ;
redef Site::local_nets += { 128.3.0.0/16, 131.243.0.0/16} ;

export { 
	global CREATE_BLACKLIST_ADHOC_CONN_LOG: bool = T ; 

        global SECS_ONE_DAY = 1 day ; #1 hrs ;
        global LOGGING_TIME = 1 hrs ; # 20 mins ; #SECS_ONE_DAY ;


	type behavior: enum {
		PERMABLOCK, 
		UNRELIABLE, 
		HAIRTRIGGER, 
		INCOMING_ONLY, 
	} ;
	
	global feed_behavior: table[behavior] of set[string] = set() ; 

	global log_reporter:function(msg: string, debug: count);
}

export { 
	global ip_drop_worthy: function(): bool ; 
	global is_permablock: function(): bool ; 
	global is_unreliable: function(): bool ; 
	global is_fedmod: function(): bool ; 
} 
	

function log_reporter(msg: string, debug: count)
{

	#if (debug < 10)
	#	return ; 

       @if ( ! Cluster::is_enabled())
        print fmt("%s", msg);
       @endif

        event reporter_info(network_time(), msg, peer_description);

}

export {


        redef enum Log::ID += { summary_LOG };

        type log_state: enum { START, EPOCH, UPDATE, ONGOING, FINISH, SUMMARY };

        type bl_stats_log: record {
                ts: time ;
                ipaddr: addr ;
                ls: log_state &default=START ;
                days_seen: count &default=0 ;
                first_seen: time &log &optional  &default=double_to_time(0.0);
                last_seen: time &log &optional  &default=double_to_time(0.0);
                active_for: string &default="" ;
                last_active: string &default="" ;
                hosts: count &default=0 ;
                total_conns: count &default=0 ;
		source: string &default ="" &optional &log ; 
        } &log ;
	
	type bl_stats_log_idx: record {
		ipaddr: addr; 
	} ; 


        type bl_stats: record {
                ts: time ;
                ipaddr: addr ;
                ls: log_state &default=START ;
                days_seen: vector of time;
                first_seen: time &log &optional  &default=double_to_time(0.0);
                last_seen: time &log &optional  &default=double_to_time(0.0);
                hosts: opaque of cardinality &default=hll_cardinality_init(0.1, 0.99);
                total_conns: count &default=0 ;
        };

        global initialize_blacklist_summary: function(ip: addr, first_seen: time);

        global bl_stats_create_expire = 20 mins ; # LOGGING_TIME &redef;
        global m_bl_stats_create_expire = LOGGING_TIME ; #LOGGING_TIME &redef;

        global aggregate_blacklist_stats: event (bs: bl_stats);

        global expire_worker_stats: function(t: table[addr] of bl_stats, idx: addr): interval;
        global worker_stats: table[addr] of bl_stats=table()
                        &create_expire=bl_stats_create_expire &expire_func=expire_worker_stats ;



        global report_manager_stats: function(t: table[addr] of bl_stats, idx: addr): interval;
        global manager_stats: table[addr] of bl_stats=table()
                        &create_expire=m_bl_stats_create_expire &expire_func=report_manager_stats ;
                        #&create_expire=30 days; 



	global log_blacklist_summary: function(bs: bl_stats); 

}

event bro_init()
{
	### initializing feed_characterstics 
	
	#feed_behavior[PERMABLOCK] = { "blacklist.master" }; 
	#feed_behavior[UNRELIABLE] = { "CFM", "FedMod" }; 
	#feed_behavior[HAIRTRIGGER] = { "blacklist.adhoc", "blacklist.tipper", "CFM", "FedMod" }; 
	#feed_behavior[INCOMING_ONLY] = { "TOR" } ; 

}
	
	

	
