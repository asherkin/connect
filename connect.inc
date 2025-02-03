#if defined _connect_included
    #endinput
#endif

#define _connect_included

enum EBeginAuthSessionResult
{
	k_EBeginAuthSessionResultOK = 0,				// Ticket is valid for this game and this steamID.
	k_EBeginAuthSessionResultInvalidTicket = 1,		// Ticket is not valid.
	k_EBeginAuthSessionResultDuplicateRequest = 2,	// A ticket has already been submitted for this steamID
	k_EBeginAuthSessionResultInvalidVersion = 3,	// Ticket is from an incompatible interface version
	k_EBeginAuthSessionResultGameMismatch = 4,		// Ticket is not for this game
	k_EBeginAuthSessionResultExpiredTicket = 5,		// Ticket has expired
};

/**
 * Called when a response to a begin authentication session request is returned
 *
 * @param steamID                         Client's Steam ID in STEAM_X:Y:Z format
 * @param eBeginAuthSessionResult         The result code
 * @return                                Change begin authentication session result
 */
forward EBeginAuthSessionResult OnBeginAuthSessionResult(const char[] steamID, EBeginAuthSessionResult eBeginAuthSessionResult);

/**
 * Called when a client attempts to connect to the server.
 *
 * @param name           Client's name
 * @param password       Client's password
 * @param ip             Client's IP address
 * @param steamID        Client's Steam ID in STEAM_X:Y:Z format
 * @param sRejectReason  Buffer to store rejection reason if player is denied access
 * @return               Allow or reject player connection
 */
forward bool OnClientPreConnectEx(const char[] name, char password[255], const char[] ip, const char[] steamID, char rejectReason[255]);

public Extension __ext_Connect = 
{
	name = "Connect",
	file = "connect.ext",
#if defined AUTOLOAD_EXTENSIONS
	autoload = 1,
#else
	autoload = 0,
#endif
#if defined REQUIRE_EXTENSIONS
	required = 1,
#else
	required = 0,
#endif
}
