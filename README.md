## Proof of Concept for cross-user Sudo RPC socket usage

This solution is a DLL injector and payload to subvert a sudo.exe into talking to another user's privileged RPC server.

### Attack scenario

1. Administrative user "A" runs sudo.exe $safecommand.
	* For PoC purposes, it's easiest to hold the RPC server open by using windbg to break on `client_DoElevationRequest`
	* In a real exploitation, the attacker would attempt to win the race to execute their command before the legitimate execution closes the RPC server
2. User "B" runs sudo-dll-injector.exe after configuring the DLL payload with the open sudo RPC socket
	* For "real" exploitation, an attacker would continiously list all processes on the system, waiting for another user to spawn a "sudo" process.
3. User "B" runs sudo.exe $attacker-command (e.g. `sudo.exe whoami /USER`)

User B's command will get ran in as User "A".
