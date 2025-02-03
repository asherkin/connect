#if defined _connect_included
    #endinput
#endif

#define _connect_included

/**
 * Steam authentication session response codes
 */
enum EAuthSessionResponse
{
	k_EAuthSessionResponseOK = 0,                            // Steam has verified the user is online, the ticket is valid and ticket has not been reused
	k_EAuthSessionResponseUserNotConnectedToSteam = 1,       // The user in question is not connected to Steam
	k_EAuthSessionResponseNoLicenseOrExpired = 2,            // The license has expired or user doesn't have license for this App ID
	k_EAuthSessionResponseVACBanned = 3,                     // The user is VAC banned for this game
	k_EAuthSessionResponseLoggedInElseWhere = 4,             // The user account has logged in elsewhere
	k_EAuthSessionResponseVACCheckTimedOut = 5,              // VAC has been unable to perform anti-cheat checks on this user
	k_EAuthSessionResponseAuthTicketCanceled = 6,            // The ticket has been canceled by the issuer
	k_EAuthSessionResponseAuthTicketInvalidAlreadyUsed = 7,  // This ticket has already been used
	k_EAuthSessionResponseAuthTicketInvalid = 8,             // This ticket is not from a user instance currently connected to Steam
	k_EAuthSessionResponsePublisherIssuedBan = 9,            // The user is banned for this game via web API
};

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
 * Called when Steam responds to an authentication ticket validation request.
 *
 * @param steamID                         Client's Steam ID in STEAM_X:Y:Z format
 * @param eAuthSessionResponse            The response code from Steam
 * @return                                Change authentication session response
 */
forward EAuthSessionResponse OnValidateAuthTicketResponse(const char[] steamID, EAuthSessionResponse eAuthSessionResponse);

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

/**
 * Call to trigger the validate auth ticket response chain
 *
 * @param steamID               Client's Steam ID64
 * @param ownerSteamID          Client's owner Steam ID64
 * @param eAuthSessionResponse  The response code from Steam
 * @return
 */
native void ValidateAuthTicketResponse(const char[] steamID, EAuthSessionResponse eAuthSessionResponse, const char[] ownerSteamID);

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

#if !defined REQUIRE_EXTENSIONS
public void __ext_connect_SetNTVOptional()
{
	MarkNativeAsOptional("ValidateAuthTicketResponse");
}
#endif
