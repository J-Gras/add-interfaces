##! Adds node's interface to logs.

module AddInterfaces;

export {
	## Enables interfaces for all active streams
	const enable_all_logs = F &redef;
	## Streams not to add interfaces for
	const exclude_logs: set[Log::ID] = { } &redef;
	## Streams to add interfaces for
	const include_logs: set[Log::ID] = { Conn::LOG } &redef;
}

global my_interface: string;

type AddedFields: record {
	interface: string &log;
};

function interface_ext_func(path: string): AddedFields
	{
	return AddedFields($interface=my_interface);
	}

event zeek_init() &priority=-3
	{
	local ps = packet_source();
	if ( ps?$live && ps$live && ps?$path )
		my_interface = ps$path;

	# This is backwards compat such that non-workers within a
	# cluster add "<node>:unknown-interface" to log entries
	# they generate. It's the only reason we depend on the
	# cluster framework at this point.
	if ( |my_interface| == 0 && Cluster::is_enabled() )
		my_interface = fmt("%s:unknown-interface", Cluster::node);

	if ( |my_interface| == 0 )
		{
		Reporter::warning("Interfaces are not added to logs!");
		return;
		}

	# Add ext_func to log streams
	for ( id in Log::active_streams )
		{
		if ( (enable_all_logs || (id in include_logs)) && (id !in exclude_logs) )
			{
			local filter = Log::get_filter(id, "default");
			filter$ext_func = interface_ext_func;
			Log::add_filter(id, filter);
			}
		}
	}
