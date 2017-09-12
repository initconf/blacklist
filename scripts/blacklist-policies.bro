module Blacklist ;

export {

        redef enum Notice::Type += {
		SynFinSeen, 
		BlacklistedDNS, 
		BlacklistedSMTP, 
		ConnectAttemptRemote, 
        } ;

} 


function ip_drop_worthy(): bool
{ 

	return (is_permablock() && ! is_unreliable()) || is_fedmod () ; 


} 

function is_permablock(): bool 
{ 

	return T ; 
} 

function is_unreliable(): bool
{
	return F ; 

} 

function is_fedmod(): bool 
{
	return T ; 
} 

event connection_established(c: connection)
{

	local orig = c$id$orig_h ;
   	local resp = c$id$resp_h ;

	local ip = orig in Site::local_nets ? resp  : orig  ; 
	local seen = bloomfilter_lookup(blacklistbloom, ip );

	if (ip !in blacklist_ip_table)
		return ; 

	if (seen > 0 && ip !in blacklist_removed )
   	{
		local _msg = fmt ("Established connection seen to blacklisted IP: [%s]",blacklist_ip_table[ip]); 
		NOTICE([$note=Blacklist::SynFinSeen, $id=c$id, $conn=c, $msg=_msg]);
	} 
}


event new_connection(c: connection)
{

	local orig = c$id$orig_h ;
        local resp = c$id$resp_h ;
        local resp_p = c$id$resp_p ;

        local ip = orig in Site::local_nets ? resp  : orig  ;

	if (ip in blacklist_removed)
		return ; 

        local seen = bloomfilter_lookup(blacklistbloom, ip );

	if (! seen )
		return ; 
	
	if (ip !in blacklist_ip_table)
		return ; 

	if (ip in LBL::LBL_NAMESERVERS && resp_p in LBL::watch_outgoing_ports)
        {
                local msg = fmt ("%s seems to be a DNS server %s", ip, blacklist_ip_table[ip]);
                NOTICE([$note=BlacklistedDNS, $msg=msg, $id=c$id, $conn=c, $identifier=cat(ip), $suppress_for=1 hrs ]);
        }
	
	if (ip in LBL::LBL_MAILSERVERS && resp_p in LBL::watch_outgoing_ports)
        {
                msg = fmt ("%s seems to be a SMTP server %s", ip, blacklist_ip_table[ip]);
                NOTICE([$note=BlacklistedSMTP, $msg=msg, $id=c$id, $conn=c, $identifier=cat(ip), $suppress_for=1 hrs ]);
        }

} 
