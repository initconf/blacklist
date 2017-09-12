module Blacklist ; 

export {

} 



event bro_init() &priority=5
{
        local filter:   Log::Filter =   [ $name="postgres_blacklist_summary",
                                        $path="blacklist_summary",
                                        $writer=Log::WRITER_POSTGRESQL,
                                        $config=table(["conninfo"]="host=localhost dbname=bro_test password=")
                                        ];

        Log::add_filter(Blacklist::summary_LOG, filter) ;
}


@if (( Cluster::is_enabled() && Cluster::local_node_type() == Cluster::MANAGER )|| ! Cluster::is_enabled() )

event bl_stats_line(description: Input::EventDescription, tpe: Input::Event, data: bl_stats_log)
    {
	local ip=data$ipaddr; 

	if (ip !in manager_stats )
	{
		local a : bl_stats; 
		manager_stats[ip]=a;
		manager_stats[ip]$days_seen=vector();
		manager_stats[ip]$days_seen[0]=data$first_seen ; 
	
		local i  = 0 ; 	
		while (i <= data$days_seen)
		{ 
			manager_stats[ip]$days_seen[i]=data$last_seen ; 
			++i; 
		} 
			
		manager_stats[ip]$first_seen=data$first_seen ; 	
		manager_stats[ip]$last_seen=data$last_seen ; 	
		manager_stats[ip]$ts=data$ts; 	
		manager_stats[ip]$total_conns=data$total_conns; 	
	} 

	#log_reporter(fmt("bl_stats_line: %s", manager_stats[ip]),0); 
	print fmt ("LLLLLLLLLLLLLL: %s", manager_stats[ip]); 
    }

event bro_init()
{

           Input::add_event( [
                        $source="select t1.* from blacklist_summary t1 JOIN (select ipaddr, MAX(ts) as max_ts from blacklist_summary group by ipaddr ) t2 ON t1.ipaddr = t2.ipaddr AND t1.ts = max_ts ;", 
			$name="manager_stats_table",
			$fields=bl_stats_log, 
                        $ev=bl_stats_line, 
                        $reader=Input::READER_POSTGRESQL,
                        $config=table(["conninfo"]="host=localhost dbname=bro_test password=")
                ]);
}

event Input::end_of_data(name: string, source:string)
        {

        log_reporter(fmt("EVENT: Input::end_of_data: VARS name: %s", name),10);
                if ( name == "manager_stats_table")
                {
                Input::remove("manager_stats_table");
                log_reporter(fmt("name: %s, size: %s", name, |manager_stats|),0);
                }
        }
@endif
