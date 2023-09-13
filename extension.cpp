/**
 * vim: set ts=4 :
 * =============================================================================
 * SourceMod Sample Extension
 * Copyright (C) 2004-2008 AlliedModders LLC.  All rights reserved.
 * =============================================================================
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License, version 3.0, as published by the
 * Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, AlliedModders LLC gives you permission to link the
 * code of this program (as well as its derivative works) to "Half-Life 2," the
 * "Source Engine," the "SourcePawn JIT," and any Game MODs that run on software
 * by the Valve Corporation.  You must obey the GNU General Public License in
 * all respects for all other code used.  Additionally, AlliedModders LLC grants
 * this exception to all derivative works.  AlliedModders LLC defines further
 * exceptions, found in LICENSE.txt (as of this writing, version JULY-31-2007),
 * or <http://www.sourcemod.net/license.php>.
 *
 * Version: $Id$
 */

#include "extension.h"
#include "extensionHelper.h"
#include "CDetour/detours.h"
#include "steam/steam_gameserver.h"
#include "sm_namehashset.h"
#include <iclient.h>
#include <netadr.h>
#include <sstream>
#include <iostream>
#include <string>
#include <map>

/**
 * @file extension.cpp
 * @brief Implement extension code here.
 */

Connect g_Connect;		/**< Global singleton for extension's main interface */
ConnectEvents g_ConnectEvents;

SMEXT_LINK(&g_Connect);

ConVar *g_ConnectVersion = CreateConVar("connect_version", SMEXT_CONF_VERSION, FCVAR_REPLICATED|FCVAR_NOTIFY, SMEXT_CONF_DESCRIPTION " Version");
ConVar *g_SvNoSteam = CreateConVar("sv_nosteam", "1", FCVAR_NOTIFY, "Disable steam validation and force steam authentication.");
ConVar *g_SvNoSteamAntiSpoof = CreateConVar("sv_nosteam_antispoof", "2", FCVAR_NOTIFY, "0 = Disable, 1 = Prevent steam users to be spoofed by nosteamers, 2 = 1 + reject incoming same nosteam id, 3 = 1 + allow incoming same nosteam id");
ConVar *g_SvConnectClientTimeout = CreateConVar("sv_connect_client_timeout", "1.0", FCVAR_NOTIFY, "How many seconds before a player is considered timed out (game crashed, lost connection...)");
ConVar *g_SvLogging = CreateConVar("sv_connect_logging", "0", FCVAR_NOTIFY, "Log connection checks");

// https://github.com/adocwang/steam_ticket_decrypter/blob/fc3ecf2a69193a7a29f5e5bffdbcda5b0b61e347/steam/steam_api_interop.cs#L9655C13-L9655C33
// https://partner.steamgames.com/doc/api/steam_api
// public enum EAuthSessionResponse
// {
// 	k_EAuthSessionResponseOK = 0, // Steam has verified the user is online, the ticket is valid and ticket has not been reused.
// 	k_EAuthSessionResponseUserNotConnectedToSteam = 1, // The user in question is not connected to steam.
// 	k_EAuthSessionResponseNoLicenseOrExpired = 2, // The user doesn't have a license for this App ID or the ticket has expired.
// 	k_EAuthSessionResponseVACBanned = 3, // The user is VAC banned for this game.
// 	k_EAuthSessionResponseLoggedInElseWhere = 4, // The user account has logged in elsewhere and the session containing the game instance has been disconnected.
// 	k_EAuthSessionResponseVACCheckTimedOut = 5, // VAC has been unable to perform anti-cheat checks on this user.
// 	k_EAuthSessionResponseAuthTicketCanceled = 6, // The ticket has been canceled by the issuer.
// 	k_EAuthSessionResponseAuthTicketInvalidAlreadyUsed = 7, // This ticket has already been used, it is not valid.
// 	k_EAuthSessionResponseAuthTicketInvalid = 8, // This ticket is not from a user instance currently connected to steam.
// 	k_EAuthSessionResponsePublisherIssuedBan = 9, // The user is banned for this game. The ban came via the web api and not VAC.
// }
ConVar *g_SvAuthSessionResponseLegal = CreateConVar("sv_auth_session_response_legal", "0,3,4,5,9", FCVAR_NOTIFY, "List of EAuthSessionResponse that are considered as Steam legal (Defined in steam_api_interop.cs).");


IGameConfig *g_pGameConf = NULL;
IForward *g_pConnectForward = NULL;
IForward *g_pOnValidateAuthTicketResponse = NULL;
IGameEventManager2 *g_pGameEvents = NULL;

class CBaseClient;
class CBaseServer;
class INetChannelInfo;
class IDemoRecorder;

class INetChannelInfo
{
public:

	enum {
		GENERIC = 0,	// must be first and is default group
		LOCALPLAYER,	// bytes for local player entity update
		OTHERPLAYERS,	// bytes for other players update
		ENTITIES,		// all other entity bytes
		SOUNDS,			// game sounds
		EVENTS,			// event messages
		USERMESSAGES,	// user messages
		ENTMESSAGES,	// entity messages
		VOICE,			// voice data
		STRINGTABLE,	// a stringtable update
		MOVE,			// client move cmds
		STRINGCMD,		// string command
		SIGNON,			// various signondata
		TOTAL,			// must be last and is not a real group
	};
	
	virtual const char  *GetName( void ) const = 0;	// get channel name
	virtual const char  *GetAddress( void ) const = 0; // get channel IP address as string
	virtual float		GetTime( void ) const = 0;	// current net time
	virtual float		GetTimeConnected( void ) const = 0;	// get connection time in seconds
	virtual int			GetBufferSize( void ) const = 0;	// netchannel packet history size
	virtual int			GetDataRate( void ) const = 0; // send data rate in byte/sec
	
	virtual bool		IsLoopback( void ) const = 0;	// true if loopback channel
	virtual bool		IsTimingOut( void ) const = 0;	// true if timing out
	virtual bool		IsPlayback( void ) const = 0;	// true if demo playback

	virtual float		GetLatency( int flow ) const = 0;	 // current latency (RTT), more accurate but jittering
	virtual float		GetAvgLatency( int flow ) const = 0; // average packet latency in seconds
	virtual float		GetAvgLoss( int flow ) const = 0;	 // avg packet loss[0..1]
	virtual float		GetAvgChoke( int flow ) const = 0;	 // avg packet choke[0..1]
	virtual float		GetAvgData( int flow ) const = 0;	 // data flow in bytes/sec
	virtual float		GetAvgPackets( int flow ) const = 0; // avg packets/sec
	virtual int			GetTotalData( int flow ) const = 0;	 // total flow in/out in bytes
	virtual int			GetSequenceNr( int flow ) const = 0;	// last send seq number
	virtual bool		IsValidPacket( int flow, int frame_number ) const = 0; // true if packet was not lost/dropped/chocked/flushed
	virtual float		GetPacketTime( int flow, int frame_number ) const = 0; // time when packet was send
	virtual int			GetPacketBytes( int flow, int frame_number, int group ) const = 0; // group size of this packet
	virtual bool		GetStreamProgress( int flow, int *received, int *total ) const = 0;  // TCP progress if transmitting
	virtual float		GetTimeSinceLastReceived( void ) const = 0;	// get time since last recieved packet in seconds
	virtual	float		GetCommandInterpolationAmount( int flow, int frame_number ) const = 0;
	virtual void		GetPacketResponseLatency( int flow, int frame_number, int *pnLatencyMsecs, int *pnChoke ) const = 0;
	virtual void		GetRemoteFramerate( float *pflFrameTime, float *pflFrameTimeStdDeviation ) const = 0;

	virtual float		GetTimeoutSeconds() const = 0;
};

abstract_class INetChannel : public INetChannelInfo
{
public:
	virtual	~INetChannel( void ) {};

	virtual void	SetDataRate(float rate) = 0;
	virtual bool	RegisterMessage(INetMessage *msg) = 0;
	virtual bool	StartStreaming( unsigned int challengeNr ) = 0;
	virtual void	ResetStreaming( void ) = 0;
	virtual void	SetTimeout(float seconds) = 0;
	virtual void	SetDemoRecorder(IDemoRecorder *recorder) = 0;
	virtual void	SetChallengeNr(unsigned int chnr) = 0;
	
	virtual void	Reset( void ) = 0;
	virtual void	Clear( void ) = 0;
	virtual void	Shutdown(const char *reason) = 0;
	
	virtual void	ProcessPlayback( void ) = 0;
	virtual bool	ProcessStream( void ) = 0;
	virtual void	ProcessPacket( struct netpacket_s* packet, bool bHasHeader ) = 0;
			
	virtual bool	SendNetMsg(INetMessage &msg, bool bForceReliable = false, bool bVoice = false ) = 0;
#ifdef POSIX
	FORCEINLINE bool SendNetMsg(INetMessage const &msg, bool bForceReliable = false, bool bVoice = false ) { return SendNetMsg( *( (INetMessage *) &msg ), bForceReliable, bVoice ); }
#endif
	virtual bool	SendData(bf_write &msg, bool bReliable = true) = 0;
	virtual bool	SendFile(const char *filename, unsigned int transferID) = 0;
	virtual void	DenyFile(const char *filename, unsigned int transferID) = 0;
	virtual void	RequestFile_OLD(const char *filename, unsigned int transferID) = 0;	// get rid of this function when we version the 
	virtual void	SetChoked( void ) = 0;
	virtual int		SendDatagram(bf_write *data) = 0;		
	virtual bool	Transmit(bool onlyReliable = false) = 0;

	virtual const netadr_t	&GetRemoteAddress( void ) const = 0;
	virtual INetChannelHandler *GetMsgHandler( void ) const = 0;
	virtual int				GetDropNumber( void ) const = 0;
	virtual int				GetSocket( void ) const = 0;
	virtual unsigned int	GetChallengeNr( void ) const = 0;
	virtual void			GetSequenceData( int &nOutSequenceNr, int &nInSequenceNr, int &nOutSequenceNrAck ) = 0;
	virtual void			SetSequenceData( int nOutSequenceNr, int nInSequenceNr, int nOutSequenceNrAck ) = 0;
		
	virtual void	UpdateMessageStats( int msggroup, int bits) = 0;
	virtual bool	CanPacket( void ) const = 0;
	virtual bool	IsOverflowed( void ) const = 0;
	virtual bool	IsTimedOut( void ) const  = 0;
	virtual bool	HasPendingReliableData( void ) = 0;

	virtual void	SetFileTransmissionMode(bool bBackgroundMode) = 0;
	virtual void	SetCompressionMode( bool bUseCompression ) = 0;
	virtual unsigned int RequestFile(const char *filename) = 0;
	virtual float	GetTimeSinceLastReceived( void ) const = 0;	// get time since last received packet in seconds

	virtual void	SetMaxBufferSize(bool bReliable, int nBytes, bool bVoice = false ) = 0;

	virtual bool	IsNull() const = 0;
	virtual int		GetNumBitsWritten( bool bReliable ) = 0;
	virtual void	SetInterpolationAmount( float flInterpolationAmount ) = 0;
	virtual void	SetRemoteFramerate( float flFrameTime, float flFrameTimeStdDeviation ) = 0;

	// Max # of payload bytes before we must split/fragment the packet
	virtual void	SetMaxRoutablePayloadSize( int nSplitSize ) = 0;
	virtual int		GetMaxRoutablePayloadSize() = 0;

	virtual int		GetProtocolVersion() = 0;
};

typedef enum EConnect
{
	k_OnClientPreConnectEx_Reject = 0,
	k_OnClientPreConnectEx_Accept = 1,
	k_OnClientPreConnectEx_Async = -1
} EConnect;

typedef enum EAuthProtocol
{
	k_EAuthProtocolWONCertificate = 1,
	k_EAuthProtocolHashedCDKey = 2,
	k_EAuthProtocolSteam = 3,
} EAuthProtocol;

const char *CSteamID::Render() const
{
	static char szSteamID[64];
	V_snprintf(szSteamID, sizeof(szSteamID), "STEAM_%u:%u:%u", 0, this->GetAccountID() & 1, this->GetAccountID() >> 1);
	return szSteamID;
}

class CSteam3Server
{
public:
	void *m_pSteamClient;
	ISteamGameServer *m_pSteamGameServer;
	void *m_pSteamGameServerUtils;
	void *m_pSteamGameServerNetworking;
	void *m_pSteamGameServerStats;
	void *m_pSteamHTTP;
	void *m_pSteamInventory;
	void *m_pSteamUGC;
	void *m_pSteamApps;
} *g_pSteam3Server;

CBaseServer *g_pBaseServer = NULL;

typedef CSteam3Server *(*Steam3ServerFunc)();

#ifndef WIN32
typedef void (*RejectConnectionFunc)(CBaseServer *, const netadr_t &address, int iClientChallenge, const char *pchReason);
#else
typedef void (__fastcall *RejectConnectionFunc)(CBaseServer *, void *, const netadr_t &address, int iClientChallenge, const char *pchReason);
#endif

#ifndef WIN32
typedef void (*SetSteamIDFunc)(CBaseClient *, const CSteamID &steamID);
#else
typedef void (__fastcall *SetSteamIDFunc)(CBaseClient *, void *, const CSteamID &steamID);
#endif

Steam3ServerFunc g_pSteam3ServerFunc = NULL;
RejectConnectionFunc g_pRejectConnectionFunc = NULL;
SetSteamIDFunc g_pSetSteamIDFunc = NULL;

CSteam3Server *Steam3Server()
{
	if(!g_pSteam3ServerFunc)
		return NULL;

	return g_pSteam3ServerFunc();
}

void RejectConnection(const netadr_t &address, int iClientChallenge, const char *pchReason)
{
	if(!g_pRejectConnectionFunc || !g_pBaseServer)
		return;

#ifndef WIN32
	g_pRejectConnectionFunc(g_pBaseServer, address, iClientChallenge, pchReason);
#else
	g_pRejectConnectionFunc(g_pBaseServer, NULL, address, iClientChallenge, pchReason);
#endif
}

void SetSteamID(CBaseClient *pClient, const CSteamID &steamID)
{
	if(!pClient || !g_pSetSteamIDFunc)
		return;

#ifndef WIN32
	g_pSetSteamIDFunc(pClient, steamID);
#else
	g_pSetSteamIDFunc(pClient, NULL, steamID);
#endif
}

EBeginAuthSessionResult BeginAuthSession(const void *pAuthTicket, int cbAuthTicket, CSteamID steamID)
{
	if(!g_pSteam3Server || !g_pSteam3Server->m_pSteamGameServer)
		return k_EBeginAuthSessionResultInvalidTicket;

	return g_pSteam3Server->m_pSteamGameServer->BeginAuthSession(pAuthTicket, cbAuthTicket, steamID);
}

void EndAuthSession(CSteamID steamID)
{
	if(!g_pSteam3Server || !g_pSteam3Server->m_pSteamGameServer)
		return;

	g_pSteam3Server->m_pSteamGameServer->EndAuthSession(steamID);
}

bool BLoggedOn()
{
	if(!g_pSteam3Server || !g_pSteam3Server->m_pSteamGameServer)
		return false;

	return g_pSteam3Server->m_pSteamGameServer->BLoggedOn();
}

bool isValidSteamID3(const std::string& input)
{
    // Check if the string starts with "[U:X:" and ends with "]"
    if (input.size() < 7 || input.substr(0, 3) != "[U:" || input.back() != ']' || !std::isdigit(input.substr(3, 1)[0]) || input.substr(4, 1) != ":") {
        return false;
    }

    // Check if the string contains digits between "[U:X:" and "]"
    for (int i = 5; i < input.size() - 1; i++) {
        if (!std::isdigit(input[i])) {
            return false;
        }
    }

    return true;
}

std::string divideByTwo(const std::string& number) {
    std::string result;
    int carry = 0;

    for (char digit : number) {
        int currentDigit = digit - '0';
        int quotient = (currentDigit + carry * 10) / 2;
        carry = (currentDigit + carry * 10) % 2;
        result.push_back(quotient + '0');
    }

    // Remove leading zeros from the result
    size_t firstNonZero = result.find_first_not_of('0');
    if (firstNonZero != std::string::npos) {
        return result.substr(firstNonZero);
    } else {
        return "0";
    }
}

bool isEven(const std::string& str) {
    // Check if the string is empty or has a single character (not a valid number)
    if (str.empty() || (str.size() == 1 && !isdigit(str[0]))) {
        return false;
    }

    // Get the last character
    char lastChar = str.back();

    // Check if the last character is a digit and it's an even number
    if (isdigit(lastChar)) {
        int lastDigit = lastChar - '0'; // Convert char to int
        return (lastDigit % 2 == 0);
    }

    return false; // Not a valid number
}

std::string SteamID3ToSteamID(const std::string& usteamid)
{
    std::string steamid = std::string(usteamid);

    if (!isValidSteamID3(steamid))
    {
        return "";
    }

    // Remove '[' and ']' characters
    steamid.erase(std::remove(steamid.begin(), steamid.end(), '['), steamid.end());
    steamid.erase(std::remove(steamid.begin(), steamid.end(), ']'), steamid.end());

    // Split the string by ':'
    std::vector<std::string> usteamid_split;
    size_t start = 0;
    size_t end = steamid.find(':');
    while (end != std::string::npos) {
        usteamid_split.push_back(steamid.substr(start, end - start));
        start = end + 1;
        end = steamid.find(':', start);
    }
    usteamid_split.push_back(steamid.substr(start, end));

    // Create a vector to store the SteamID components
    std::vector<std::string> steamid_components;
    steamid_components.push_back("STEAM_0:");

    if (isEven(usteamid_split[2])) {
        steamid_components.push_back("0:");
    } else {
        steamid_components.push_back("1:");
    }

    std::string steamacct = divideByTwo(usteamid_split[2]);
    steamid_components.push_back(steamacct);

    // Concatenate the components to form the SteamID
    steamid = "";
    for (const std::string& component : steamid_components) {
        steamid += component;
    }

    return steamid;
}

CDetour *g_Detour_CBaseServer__ConnectClient = NULL;
CDetour *g_Detour_CBaseServer__RejectConnection = NULL;
CDetour *g_Detour_CBaseServer__CheckChallengeType = NULL;
CDetour *g_Detour_CSteam3Server__OnValidateAuthTicketResponse = NULL;

class ConnectClientStorage
{
public:
	void* pThis;

	netadr_t address;
	int nProtocol;
	int iChallenge;
	int iClientChallenge;
	int nAuthProtocol;
	char pchName[256];
	char pchPassword[256];
	char hashedCDkey[256];
	int cdKeyLen;
	IClient *pClient;

	uint64 ullSteamID;
	ValidateAuthTicketResponse_t ValidateAuthTicketResponse;
	bool GotValidateAuthTicketResponse;
	bool SteamLegal;
	bool SteamAuthFailed;
	EAuthSessionResponse eAuthSessionResponse;
	bool async;
	bool clientPreConnectExCalled;
	int userid;

	ConnectClientStorage()
	{
		this->GotValidateAuthTicketResponse = false;
		this->SteamLegal = false;
		this->SteamAuthFailed = false;
		this->eAuthSessionResponse = k_EAuthSessionResponseAuthTicketInvalid;
		this->async = false;
		this->clientPreConnectExCalled = false;
		this->userid = -1;
	}
	ConnectClientStorage(netadr_t address, int nProtocol, int iChallenge, int iClientChallenge, int nAuthProtocol, const char *pchName, const char *pchPassword, const char *hashedCDkey, int cdKeyLen)
	{
		this->address = address;
		this->nProtocol = nProtocol;
		this->iChallenge = iChallenge;
		this->iClientChallenge = iClientChallenge;
		this->nAuthProtocol = nAuthProtocol;
		strncpy(this->pchName, pchName, sizeof(this->pchName));
		strncpy(this->pchPassword, pchPassword, sizeof(this->pchPassword));
		strncpy(this->hashedCDkey, hashedCDkey, sizeof(this->hashedCDkey));
		this->cdKeyLen = cdKeyLen;
		this->pClient = NULL;
		this->GotValidateAuthTicketResponse = false;
		this->SteamLegal = false;
		this->SteamAuthFailed = false;
		this->eAuthSessionResponse = k_EAuthSessionResponseAuthTicketInvalid;
		this->async = false;
		this->clientPreConnectExCalled = false;
		this->userid = -1;
	}
};
StringHashMap<ConnectClientStorage> g_ConnectClientStorage;

bool g_bEndAuthSessionOnRejectConnection = false;
CSteamID g_lastClientSteamID;
bool g_bSuppressCheckChallengeType = false;

bool IsAuthSessionResponseSteamLegal(EAuthSessionResponse eAuthSessionResponse)
{
	std::stringstream ss(g_SvAuthSessionResponseLegal->GetString());
	int legalAuthSessionResponse[10];
	char ch;
	int n;
	int size = 0;

	while(ss >> n)
	{
		if(ss >> ch)
			legalAuthSessionResponse[size] = n;
		else
			legalAuthSessionResponse[size] = n;
		size++;
	}

	for (int y = 0; y < size; y++)
	{
	    if (eAuthSessionResponse == legalAuthSessionResponse[y])
	        return true;
	}
	return false;
}

DETOUR_DECL_MEMBER1(CSteam3Server__OnValidateAuthTicketResponse, int, ValidateAuthTicketResponse_t *, pResponse)
{
	char aSteamID[64];
	strncpy(aSteamID, pResponse->m_SteamID.Render(), sizeof(aSteamID) - 1);

	ConnectClientStorage Storage;
	bool StorageValid = g_ConnectClientStorage.retrieve(aSteamID, &Storage);

	EAuthSessionResponse eAuthSessionResponse = pResponse->m_eAuthSessionResponse;
	bool SteamLegal = IsAuthSessionResponseSteamLegal(pResponse->m_eAuthSessionResponse);

	if (SteamLegal || (!SteamLegal && g_SvNoSteam->GetInt()))
		pResponse->m_eAuthSessionResponse = k_EAuthSessionResponseOK;

	if (g_SvLogging->GetInt())
		g_pSM->LogMessage(myself, "%s SteamLegal: %d (%d)", aSteamID, SteamLegal, pResponse->m_eAuthSessionResponse);

	if (StorageValid && !Storage.GotValidateAuthTicketResponse)
	{
		Storage.GotValidateAuthTicketResponse = true;
		Storage.ValidateAuthTicketResponse = *pResponse;
		Storage.SteamLegal = SteamLegal;
		Storage.eAuthSessionResponse = eAuthSessionResponse;
		g_ConnectClientStorage.replace(aSteamID, Storage);
	}

	g_pOnValidateAuthTicketResponse->PushCell(Storage.eAuthSessionResponse);
	g_pOnValidateAuthTicketResponse->PushCell(Storage.GotValidateAuthTicketResponse);
	g_pOnValidateAuthTicketResponse->PushCell(Storage.SteamLegal);
	g_pOnValidateAuthTicketResponse->PushStringEx(aSteamID, sizeof(aSteamID), SM_PARAM_STRING_UTF8 | SM_PARAM_STRING_COPY, SM_PARAM_COPYBACK);
	g_pOnValidateAuthTicketResponse->Execute();

	return DETOUR_MEMBER_CALL(CSteam3Server__OnValidateAuthTicketResponse)(pResponse);
}

DETOUR_DECL_MEMBER9(CBaseServer__ConnectClient, IClient *, netadr_t &, address, int, nProtocol, int, iChallenge, int, iClientChallenge, int, nAuthProtocol, const char *, pchName, const char *, pchPassword, const char *, hashedCDkey, int, cdKeyLen)
{
	if (nAuthProtocol != k_EAuthProtocolSteam)
	{
		// This is likely a SourceTV client, we don't want to interfere here.
		return DETOUR_MEMBER_CALL(CBaseServer__ConnectClient)(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, hashedCDkey, cdKeyLen);
	}

	g_pBaseServer = (CBaseServer *)this;

	if (hashedCDkey == NULL || (size_t)cdKeyLen < sizeof(uint64))
	{
		RejectConnection(address, iClientChallenge, "#GameUI_ServerRejectInvalidSteamCertLen");
		return NULL;
	}

	char ipString[32];
	V_snprintf(ipString, sizeof(ipString), "%u.%u.%u.%u", address.ip[0], address.ip[1], address.ip[2], address.ip[3]);

	char passwordBuffer[255];
	strncpy(passwordBuffer, pchPassword, sizeof(passwordBuffer));
	uint64 ullSteamID = *(uint64 *)hashedCDkey;

	void *pvTicket = (void *)((intptr_t)hashedCDkey + sizeof(uint64));
	int cbTicket = cdKeyLen - sizeof(uint64);

	g_bEndAuthSessionOnRejectConnection = true;
	g_lastClientSteamID = CSteamID(ullSteamID);

	char aSteamID[64];
	strncpy(aSteamID, g_lastClientSteamID.Render(), sizeof(aSteamID));

	ConnectClientStorage Storage(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, hashedCDkey, cdKeyLen);

	EBeginAuthSessionResult result = BeginAuthSession(pvTicket, cbTicket, g_lastClientSteamID);
	if (result != k_EBeginAuthSessionResultOK)
	{
		if(!g_SvNoSteam->GetInt())
		{
			RejectConnection(address, iClientChallenge, "#GameUI_ServerRejectSteam");
			return NULL;
		}
		Storage.SteamAuthFailed = true;
	}

	ConnectClientStorage ExistingStorage;
	bool ExistingStorageStored = g_ConnectClientStorage.retrieve(aSteamID, &ExistingStorage);

	if (g_SvLogging->GetInt())
		g_pSM->LogMessage(myself, "%s ExistingStorageStored: %d, SteamAuthFailed: %d (%d), Async: %d", aSteamID, ExistingStorageStored, Storage.SteamAuthFailed, result, ExistingStorage.async);

	if (ExistingStorageStored && !ExistingStorage.async)
	{
		// Check if player has timed out (game crashed, lost connection...)
		bool timedOut = false;
		if (ExistingStorage.pClient && ExistingStorage.pClient->IsConnected())
		{
			if (g_SvLogging->GetInt())
				g_pSM->LogMessage(myself, "[TIMEOUT] %s ExistingStorageStored: %d, SteamAuthFailed: %d (%d), Async: %d", aSteamID, ExistingStorageStored, Storage.SteamAuthFailed, result, ExistingStorage.async);

			INetChannel *netchan = ExistingStorage.pClient->GetNetChannel();
			if (!netchan)
			{
				timedOut = true;
			}
			else
			{
				if (g_SvLogging->GetInt())
					g_pSM->LogMessage(myself, "[TIMEOUT] %s %f", aSteamID, netchan->GetTimeSinceLastReceived());

				if (netchan->GetTimeSinceLastReceived() > g_SvConnectClientTimeout->GetFloat())
				{
					if (g_SvLogging->GetInt())
						g_pSM->LogMessage(myself, "[TIMEOUT] %s timed out!", aSteamID);

					timedOut = true;
				}
			}
		}

		if (g_SvNoSteamAntiSpoof->GetInt())
		{
			// Incoming NoSteam player trying to spoof steam player
			if (Storage.SteamAuthFailed && !ExistingStorage.SteamAuthFailed)
			{
				RejectConnection(address, iClientChallenge, "You are not connected to steam, please try again.");
				return NULL;
			}
			// Incoming steam player currently spoofed by NoSteamer
			else if (!Storage.SteamAuthFailed && ExistingStorage.SteamAuthFailed)
			{
				// Dont do anything to let the original ConnectClient function
				// disconnect the existing player
				if (ExistingStorage.pClient)
				{
					g_bEndAuthSessionOnRejectConnection = false;
					ExistingStorage.pClient->Disconnect("Same Steam ID connected.");
					g_bEndAuthSessionOnRejectConnection = true;
				}
				g_ConnectClientStorage.remove(aSteamID);
				ExistingStorageStored = false;
			}
			// Incoming NoSteam player trying to spoof NoSteam player
			// Check if its not the same player trying to reconnect
			// If he either timed out or if its exactly the same ip address and port
			else if (g_SvNoSteamAntiSpoof->GetInt() == 2 && Storage.SteamAuthFailed && ExistingStorage.SteamAuthFailed && !timedOut && !address.CompareAdr(ExistingStorage.address, false))
			{
				RejectConnection(address, iClientChallenge, "NoSteam ID already in use.");
				return NULL;
			}
		}
	}

	char rejectReason[255];
	cell_t retVal = k_OnClientPreConnectEx_Accept;

	if (ExistingStorageStored && ExistingStorage.async)
	{
		// if client auto-retries while ClientPreConnectEx has still not been called
		if (!ExistingStorage.clientPreConnectExCalled)
			retVal = k_OnClientPreConnectEx_Async;
	}
	else
	{
		g_pConnectForward->PushString(pchName);
		g_pConnectForward->PushStringEx(passwordBuffer, sizeof(passwordBuffer), SM_PARAM_STRING_UTF8 | SM_PARAM_STRING_COPY, SM_PARAM_COPYBACK);
		g_pConnectForward->PushString(ipString);
		g_pConnectForward->PushString(aSteamID);
		g_pConnectForward->PushStringEx(rejectReason, sizeof(rejectReason), SM_PARAM_STRING_UTF8 | SM_PARAM_STRING_COPY, SM_PARAM_COPYBACK);
		g_pConnectForward->Execute(&retVal);
		pchPassword = passwordBuffer;
	}

	if (g_SvLogging->GetInt())
		g_pSM->LogMessage(myself, "%s SteamAuthFailed: %d (%d) | retVal = %d", aSteamID, Storage.SteamAuthFailed, result, retVal);

	if (retVal == k_OnClientPreConnectEx_Reject)
	{
		g_ConnectClientStorage.remove(aSteamID);
		RejectConnection(address, iClientChallenge, rejectReason);
		return NULL;
	}

	Storage.pThis = this;
	Storage.ullSteamID = ullSteamID;
	Storage.async = retVal == k_OnClientPreConnectEx_Async;

	if (!g_ConnectClientStorage.replace(aSteamID, Storage))
	{
		RejectConnection(address, iClientChallenge, "Internal error.");
		return NULL;
	}

	// If async, ClientPreConnectEx will trigger normal auth session mechanism
	if (Storage.async)
	{
		EndAuthSession(g_lastClientSteamID);
		return NULL;
	}

	g_bSuppressCheckChallengeType = true;
	IClient *pClient = DETOUR_MEMBER_CALL(CBaseServer__ConnectClient)(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, hashedCDkey, cdKeyLen);

	Storage.pClient = pClient;
	g_ConnectClientStorage.replace(aSteamID, Storage);

	if (pClient && Storage.SteamAuthFailed)
	{
		ValidateAuthTicketResponse_t Response;
		Response.m_SteamID = g_lastClientSteamID;
		Response.m_eAuthSessionResponse = k_EAuthSessionResponseAuthTicketInvalid;
		Response.m_OwnerSteamID = Response.m_SteamID;
		DETOUR_MEMBER_MCALL_CALLBACK(CSteam3Server__OnValidateAuthTicketResponse, g_pSteam3Server)(&Response);
	}

	return pClient;
}

DETOUR_DECL_MEMBER3(CBaseServer__RejectConnection, void, netadr_t &, address, int, iClientChallenge, const char *, pchReason)
{
	if(g_bEndAuthSessionOnRejectConnection)
	{
		EndAuthSession(g_lastClientSteamID);
		g_bEndAuthSessionOnRejectConnection = false;
	}

	return DETOUR_MEMBER_CALL(CBaseServer__RejectConnection)(address, iClientChallenge, pchReason);
}

DETOUR_DECL_MEMBER7(CBaseServer__CheckChallengeType, bool, CBaseClient *, pClient, int, nUserID, netadr_t &, address, int, nAuthProtocol, const char *, hashedCDkey, int, cdKeyLen, int, iClientChallenge)
{
	if(g_bSuppressCheckChallengeType)
	{
		g_bEndAuthSessionOnRejectConnection = false;

		SetSteamID(pClient, g_lastClientSteamID);

		g_bSuppressCheckChallengeType = false;
		return true;
	}

	return DETOUR_MEMBER_CALL(CBaseServer__CheckChallengeType)(pClient, nUserID, address, nAuthProtocol, hashedCDkey, cdKeyLen, iClientChallenge);
}


bool Connect::SDK_OnLoad(char *error, size_t maxlen, bool late)
{
	char conf_error[255] = "";
	if(!gameconfs->LoadGameConfigFile("connect2.games", &g_pGameConf, conf_error, sizeof(conf_error)))
	{
		if(conf_error[0])
		{
			snprintf(error, maxlen, "Could not read connect2.games.txt: %s\n", conf_error);
		}
		return false;
	}

	if(!g_pGameConf->GetMemSig("CBaseServer__RejectConnection", (void **)(&g_pRejectConnectionFunc)) || !g_pRejectConnectionFunc)
	{
		snprintf(error, maxlen, "Failed to find CBaseServer__RejectConnection function.\n");
		return false;
	}

	if(!g_pGameConf->GetMemSig("CBaseClient__SetSteamID", (void **)(&g_pSetSteamIDFunc)) || !g_pSetSteamIDFunc)
	{
		snprintf(error, maxlen, "Failed to find CBaseClient__SetSteamID function.\n");
		return false;
	}

#ifndef WIN32
	if(!g_pGameConf->GetMemSig("Steam3Server", (void **)(&g_pSteam3ServerFunc)) || !g_pSteam3ServerFunc)
	{
		snprintf(error, maxlen, "Failed to find Steam3Server function.\n");
		return false;
	}
#else
	void *address;
	if(!g_pGameConf->GetMemSig("CBaseServer__CheckMasterServerRequestRestart", &address) || !address)
	{
		snprintf(error, maxlen, "Failed to find CBaseServer__CheckMasterServerRequestRestart function.\n");
		return false;
	}

	//META_CONPRINTF("CheckMasterServerRequestRestart: %p\n", address);
	address = (void *)((intptr_t)address + 1); // Skip CALL opcode
	intptr_t offset = (intptr_t)(*(void **)address); // Get offset

	g_pSteam3ServerFunc = (Steam3ServerFunc)((intptr_t)address + offset + sizeof(intptr_t));
	//META_CONPRINTF("Steam3Server: %p\n", g_pSteam3ServerFunc);
#endif

	g_pSteam3Server = Steam3Server();
	if(!g_pSteam3Server)
	{
		snprintf(error, maxlen, "Unable to get Steam3Server singleton.\n");
		return false;
	}

	/*
	META_CONPRINTF("ISteamGameServer: %p\n", g_pSteam3Server->m_pSteamGameServer);
	META_CONPRINTF("ISteamUtils: %p\n", g_pSteam3Server->m_pSteamGameServerUtils);
	META_CONPRINTF("ISteamMasterServerUpdater: %p\n", g_pSteam3Server->m_pSteamMasterServerUpdater);
	META_CONPRINTF("ISteamNetworking: %p\n", g_pSteam3Server->m_pSteamGameServerNetworking);
	META_CONPRINTF("ISteamGameServerStats: %p\n", g_pSteam3Server->m_pSteamGameServerStats);
	*/

	CDetourManager::Init(g_pSM->GetScriptingEngine(), g_pGameConf);

	g_Detour_CBaseServer__ConnectClient = DETOUR_CREATE_MEMBER(CBaseServer__ConnectClient, "CBaseServer__ConnectClient");
	if(!g_Detour_CBaseServer__ConnectClient)
	{
		snprintf(error, maxlen, "Failed to detour CBaseServer__ConnectClient.\n");
		return false;
	}
	g_Detour_CBaseServer__ConnectClient->EnableDetour();

	g_Detour_CBaseServer__RejectConnection = DETOUR_CREATE_MEMBER(CBaseServer__RejectConnection, "CBaseServer__RejectConnection");
	if(!g_Detour_CBaseServer__RejectConnection)
	{
		snprintf(error, maxlen, "Failed to detour CBaseServer__RejectConnection.\n");
		return false;
	}
	g_Detour_CBaseServer__RejectConnection->EnableDetour();

	g_Detour_CBaseServer__CheckChallengeType = DETOUR_CREATE_MEMBER(CBaseServer__CheckChallengeType, "CBaseServer__CheckChallengeType");
	if(!g_Detour_CBaseServer__CheckChallengeType)
	{
		snprintf(error, maxlen, "Failed to detour CBaseServer__CheckChallengeType.\n");
		return false;
	}
	g_Detour_CBaseServer__CheckChallengeType->EnableDetour();

	g_Detour_CSteam3Server__OnValidateAuthTicketResponse = DETOUR_CREATE_MEMBER(CSteam3Server__OnValidateAuthTicketResponse, "CSteam3Server__OnValidateAuthTicketResponse");
	if(!g_Detour_CSteam3Server__OnValidateAuthTicketResponse)
	{
		snprintf(error, maxlen, "Failed to detour CSteam3Server__OnValidateAuthTicketResponse.\n");
		return false;
	}
	g_Detour_CSteam3Server__OnValidateAuthTicketResponse->EnableDetour();

	g_pConnectForward = g_pForwards->CreateForward("OnClientPreConnectEx", ET_LowEvent, 5, NULL, Param_String, Param_String, Param_String, Param_String, Param_String);
	g_pOnValidateAuthTicketResponse = g_pForwards->CreateForward("OnValidateAuthTicketResponse", ET_Ignore, 4, NULL, Param_Cell, Param_Cell, Param_Cell, Param_String);

	g_pGameEvents->AddListener(&g_ConnectEvents, "player_connect", true);
	g_pGameEvents->AddListener(&g_ConnectEvents, "player_disconnect", true);

	playerhelpers->AddClientListener(this);

	AutoExecConfig(g_pCVar, true);

	return true;
}

bool Connect::SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	GET_V_IFACE_CURRENT(GetEngineFactory, engine, IVEngineServer, INTERFACEVERSION_VENGINESERVER);
	GET_V_IFACE_ANY(GetServerFactory, gamedll, IServerGameDLL, INTERFACEVERSION_SERVERGAMEDLL);
	GET_V_IFACE_CURRENT(GetEngineFactory, g_pGameEvents, IGameEventManager2, INTERFACEVERSION_GAMEEVENTSMANAGER2);
	GET_V_IFACE_CURRENT(GetEngineFactory, g_pCVar, ICvar, CVAR_INTERFACE_VERSION);

	ConVar_Register(0, this);

	return true;
}

void Connect::SDK_OnUnload()
{
	if(g_pConnectForward)
		g_pForwards->ReleaseForward(g_pConnectForward);

	if(g_pOnValidateAuthTicketResponse)
		g_pForwards->ReleaseForward(g_pOnValidateAuthTicketResponse);

	if(g_Detour_CBaseServer__ConnectClient)
	{
		g_Detour_CBaseServer__ConnectClient->Destroy();
		g_Detour_CBaseServer__ConnectClient = NULL;
	}
	if(g_Detour_CBaseServer__RejectConnection)
	{
		g_Detour_CBaseServer__RejectConnection->Destroy();
		g_Detour_CBaseServer__RejectConnection = NULL;
	}
	if(g_Detour_CBaseServer__CheckChallengeType)
	{
		g_Detour_CBaseServer__CheckChallengeType->Destroy();
		g_Detour_CBaseServer__CheckChallengeType = NULL;
	}
	if(g_Detour_CSteam3Server__OnValidateAuthTicketResponse)
	{
		g_Detour_CSteam3Server__OnValidateAuthTicketResponse->Destroy();
		g_Detour_CSteam3Server__OnValidateAuthTicketResponse = NULL;
	}

	g_pGameEvents->RemoveListener(&g_ConnectEvents);

	playerhelpers->RemoveClientListener(this);

	gameconfs->CloseGameConfigFile(g_pGameConf);
}

bool Connect::RegisterConCommandBase(ConCommandBase *pVar)
{
	/* Always call META_REGCVAR instead of going through the engine. */
	return META_REGCVAR(pVar);
}

cell_t ClientPreConnectEx(IPluginContext *pContext, const cell_t *params)
{
	char *pSteamID;
	pContext->LocalToString(params[1], &pSteamID);

	int retVal = params[2];

	char *rejectReason;
	pContext->LocalToString(params[3], &rejectReason);

	ConnectClientStorage Storage;
	if (!g_ConnectClientStorage.retrieve(pSteamID, &Storage))
		return 1;

	if (retVal == k_OnClientPreConnectEx_Reject)
	{
		RejectConnection(Storage.address, Storage.iClientChallenge, rejectReason);
		return 0;
	}

	// Notify that synchronous function has been called
	Storage.clientPreConnectExCalled = true;
	g_ConnectClientStorage.replace(pSteamID, Storage);

	g_bSuppressCheckChallengeType = true;
	IClient *pClient = DETOUR_MEMBER_MCALL_ORIGINAL(CBaseServer__ConnectClient, Storage.pThis)(Storage.address, Storage.nProtocol, Storage.iChallenge, Storage.iClientChallenge,
		Storage.nAuthProtocol, Storage.pchName, Storage.pchPassword, Storage.hashedCDkey, Storage.cdKeyLen);

	if (!pClient)
		return 1;

	if (Storage.SteamAuthFailed && g_SvNoSteam->GetInt() && !Storage.GotValidateAuthTicketResponse)
	{
		if (g_SvLogging->GetInt())
			g_pSM->LogMessage(myself, "%s Force ValidateAuthTicketResponse", pSteamID);

		Storage.ValidateAuthTicketResponse.m_SteamID = CSteamID(Storage.ullSteamID);
		Storage.ValidateAuthTicketResponse.m_eAuthSessionResponse = k_EAuthSessionResponseOK;
		Storage.ValidateAuthTicketResponse.m_OwnerSteamID = Storage.ValidateAuthTicketResponse.m_SteamID;
		Storage.GotValidateAuthTicketResponse = true;
	}

	// Make sure this is always called in order to verify the client on the server
	if(Storage.GotValidateAuthTicketResponse)
	{
		if (g_SvLogging->GetInt())
			g_pSM->LogMessage(myself, "%s Replay ValidateAuthTicketResponse", pSteamID);

		DETOUR_MEMBER_MCALL_ORIGINAL(CSteam3Server__OnValidateAuthTicketResponse, g_pSteam3Server)(&Storage.ValidateAuthTicketResponse);
	}

	return 0;
}

cell_t SteamClientAuthenticated(IPluginContext *pContext, const cell_t *params)
{
	char *pSteamID;
	pContext->LocalToString(params[1], &pSteamID);

	ConnectClientStorage Storage;
	if(g_ConnectClientStorage.retrieve(pSteamID, &Storage))
	{
		if (g_SvLogging->GetInt())
			g_pSM->LogMessage(myself, "%s SteamClientAuthenticated: %d", pSteamID, Storage.SteamLegal);

		return Storage.SteamLegal;
	}
	if (g_SvLogging->GetInt())
		g_pSM->LogMessage(myself, "%s SteamClientAuthenticated: FALSE!", pSteamID);

	return false;
}

cell_t SteamClientGotValidateAuthTicketResponse(IPluginContext *pContext, const cell_t *params)
{
	char *pSteamID;
	pContext->LocalToString(params[1], &pSteamID);

	ConnectClientStorage Storage;
	if (g_ConnectClientStorage.retrieve(pSteamID, &Storage))
	{
		if (g_SvLogging->GetInt())
			g_pSM->LogMessage(myself, "%s SteamClientGotValidateAuthTicketResponse: %d", pSteamID, Storage.GotValidateAuthTicketResponse);

		return Storage.GotValidateAuthTicketResponse;
	}
	if (g_SvLogging->GetInt())
		g_pSM->LogMessage(myself, "%s SteamClientGotValidateAuthTicketResponse: FALSE!", pSteamID);

	return false;
}

const sp_nativeinfo_t MyNatives[] =
{
	{ "ClientPreConnectEx", ClientPreConnectEx },
	{ "SteamClientAuthenticated", SteamClientAuthenticated },
	{ "SteamClientGotValidateAuthTicketResponse", SteamClientGotValidateAuthTicketResponse},
	{ NULL, NULL }
};

void Connect::SDK_OnAllLoaded()
{
	sharesys->AddNatives(myself, MyNatives);
}

std::map<int, std::string> g_useridToSteamID;

void ConnectEvents::FireGameEvent(IGameEvent *event)
{
	const char *name = event->GetName();

	if (strcmp(name, "player_connect") == 0)
	{
		const int userid = event->GetInt("userid");
		const bool bot = event->GetBool("bot");
		const char *networkid = event->GetString("networkid");

		if (g_SvLogging->GetInt())
			g_pSM->LogMessage(myself, "player_connect(user_id=%d, networkid=%s, bot=%d)", userid, networkid, bot);

		if (bot) {
			return;
		}

		std::string steamid = SteamID3ToSteamID(networkid);

		if (!steamid.empty()) {
			if (g_SvLogging->GetInt())
				g_pSM->LogMessage(myself, "%s OnClientConnecting", steamid.c_str());

			if (g_useridToSteamID.count(userid) > 0) {
				g_useridToSteamID.erase(userid);
			}

			g_useridToSteamID.insert(std::make_pair(userid, steamid));
		}
	}
	else if (strcmp(name, "player_disconnect") == 0)
	{
		const int userid = event->GetInt("userid");
		const bool bot = event->GetBool("bot");
		const char *networkid = event->GetString("networkid");

		if (g_SvLogging->GetInt())
			g_pSM->LogMessage(myself, "player_disconnect(user_id=%d, networkid=%s, bot=%d)", userid, networkid, bot);

		if (bot) {
			return;
		}

		std::string steamid = SteamID3ToSteamID(networkid);
		if (g_useridToSteamID.count(userid) > 0)
		{
			std::string savedSteamID = g_useridToSteamID[userid];
			if (steamid != savedSteamID) {
				if (g_SvLogging->GetInt())
					g_pSM->LogMessage(myself, "%s Tried to disconnect with steam id %s", savedSteamID.c_str(), steamid.c_str());
				steamid = savedSteamID;
			}
		}

		if (!steamid.empty()) {
			if (g_SvLogging->GetInt())
				g_pSM->LogMessage(myself, "%s OnClientDisconnecting", steamid.c_str());

			g_ConnectClientStorage.remove(steamid.c_str());
		}
	}
}
