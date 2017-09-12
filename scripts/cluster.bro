@if ( Cluster::local_node_type() == Cluster::MANAGER )
# Handling of new worker nodes.
event remote_connection_handshake_done(p: event_peer)
        {
        # When a worker connects, send it the complete minimal data store.
        # It will be kept up to date after this by the cluster_new_item event.
        if ( Cluster::nodes[p$descr]$node_type == Cluster::WORKER )
                {
                send_id(p, "Blacklist::blacklist_ip_table");
                }
        }
@endif 
