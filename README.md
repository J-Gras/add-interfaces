# Add-Interfaces

This package adds the `_interface` field to Bro logs to indicate which
interface generated a log entry. By default the field is only added to
the `conn.log`. For further configuration, the following options are
available:

Option                       | Default Value   | Description
-----------------------------|-----------------|-------------------------------------------
`enable_all_logs: bool`      | `F`             | Enables interfaces for all active streams
`exclude_logs: set[Log::ID]` | `{ }`           | Streams **not** to add interfaces for
`include_logs: set[Log::ID]` | `{ Conn::LOG }` | Streams to add interfaces for

If Bro is not executed in cluster mode, the field is not added.
