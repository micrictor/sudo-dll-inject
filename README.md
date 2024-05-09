## Proof of Concept for cross-user Sudo RPC socket usage

This solution is a DLL injector and payload to subvert a sudo.exe into talking to another user's privileged RPC server.

### Attack scenario

1. Administrative user "A" runs sudo.exe $safecommand.
	* For PoC purposes, it's easiest to hold the RPC server open by using windbg to break on `client_DoElevationRequest`
	* In a real exploitation, the attacker would attempt to win the race to execute their command before the legitimate execution closes the RPC server
1. User "B" runs sudo-dll-injector.exe after configuring the DLL payload with the open sudo RPC socket
1. User "B" runs sudo.exe $attacker-command (e.g. `sudo.exe whoami /USER`)
	* Note that I didn't patch out the elevation request here, so you still must positively ack the UAC request.
	* An attacker could trivially further hook methods to avoid this, but I haven't yet :)

User B's command will get ran in as User "A".
