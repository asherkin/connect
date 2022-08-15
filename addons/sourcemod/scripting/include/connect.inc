#if defined _Connect_Included
 #endinput
#endif
#define _Connect_Included

enum EConnect
{
	k_OnClientPreConnectEx_Reject = 0,
	k_OnClientPreConnectEx_Accept = 1,
	k_OnClientPreConnectEx_Async = -1
};

enum EAuthSessionResponse
{
	k_EAuthSessionResponseOK = 0,
	k_EAuthSessionResponseUserNotConnectedToSteam = 1,
	k_EAuthSessionResponseNoLicenseOrExpired = 2,
	k_EAuthSessionResponseVACBanned = 3,
	k_EAuthSessionResponseLoggedInElseWhere = 4,
	k_EAuthSessionResponseVACCheckTimedOut = 5,
	k_EAuthSessionResponseAuthTicketCanceled = 6,
	k_EAuthSessionResponseAuthTicketInvalidAlreadyUsed = 7,
	k_EAuthSessionResponseAuthTicketInvalid = 8,
	k_EAuthSessionResponsePublisherIssuedBan = 9,
}

forward EConnect OnClientPreConnectEx(const char[] sName, char sPassword[255], const char[] sIP, const char[] sSteam32ID, char sRejectReason[255]);
forward void OnValidateAuthTicketResponse(EAuthSessionResponse eAuthSessionResponse, bool bGotValidateAuthTicketResponse, bool bSteamLegal, char sSteam32ID[32]);

native bool ClientPreConnectEx(const char[] sSteam32ID, EConnect RetVal, char sRejectReason[255]);
native bool SteamClientAuthenticated(const char[] sSteam32ID);
native bool SteamClientGotValidateAuthTicketResponse(const char[] sSteam32ID);

/**
 * Do not edit below this line!
 */
public Extension __ext_connect =
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
};

#if !defined REQUIRE_EXTENSIONS
public void __ext_connect_SetNTVOptional()
{
	MarkNativeAsOptional("ClientPreConnectEx");
}
#endif
