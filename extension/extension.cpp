/*
 * =============================================================================
 * Connect Extension
 * Copyright (C) 2011 Asher Baker (asherkin).  All rights reserved.
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
 */

#include "extension.h"
#include "CDetour/detours.h"

#include "steam/steamclientpublic.h"
#include "tier1/netadr.h"
#include "inetchannel.h"
#include <string>

Connect g_connect;

SMEXT_LINK(&g_connect);

ConVar connectVersion("connect_version", SMEXT_CONF_VERSION, FCVAR_SPONLY|FCVAR_REPLICATED|FCVAR_NOTIFY, SMEXT_CONF_DESCRIPTION " Version");

IGameConfig *g_pGameConf = NULL;

IForward *g_pConnectForward = NULL;

class IClient;
class CBaseClient;

class CBaseServer;

#define CONNECTIONLESS_HEADER	0xFFFFFFFF
#define S2C_CONNREJECT			'9'
#define MAX_ROUTABLE_PAYLOAD	1260

enum
{
	NS_CLIENT = 0,
	NS_SERVER,
	NS_HLTV,
	NS_MATCHMAKING,
	NS_SYSTEMLINK,
#ifdef LINUX
	NS_SVLAN,
#endif
	MAX_SOCKETS
};

typedef enum EAuthProtocol
{
	k_EAuthProtocolWONCertificate = 1,
	k_EAuthProtocolHashedCDKey = 2,
	k_EAuthProtocolSteam = 3,
} EAuthProtocol;

#if SOURCE_ENGINE == SE_LEFT4DEAD || SOURCE_ENGINE == SE_LEFT4DEAD2
typedef enum EBeginAuthSessionResult
{
	k_EBeginAuthSessionResultOK = 0,				// Ticket is valid for this game and this steamID.
	k_EBeginAuthSessionResultInvalidTicket = 1,		// Ticket is not valid.
	k_EBeginAuthSessionResultDuplicateRequest = 2,	// A ticket has already been submitted for this steamID
	k_EBeginAuthSessionResultInvalidVersion = 3,	// Ticket is from an incompatible interface version
	k_EBeginAuthSessionResultGameMismatch = 4,		// Ticket is not for this game
	k_EBeginAuthSessionResultExpiredTicket = 5,		// Ticket has expired
} EBeginAuthSessionResult;
#endif

const char *CSteamID::Render() const
{
	static char szSteamID[64];
	V_snprintf(szSteamID, sizeof(szSteamID), "STEAM_0:%u:%u", this->GetAccountID() & 1, this->GetAccountID() >> 1);
	return szSteamID;
}

class CSteam3Server
{
public:
	void *m_pSteamClient;
	void *m_pSteamGameServer;
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

#if !defined(WIN32) || defined(WIN64)
typedef void (*RejectConnectionFunc)(CBaseServer *, const netadr_t &address, int iClientChallenge, const char *pchReason);
#else
typedef void (__fastcall *RejectConnectionFunc)(CBaseServer *, void *, const netadr_t &address, int iClientChallenge, const char *pchReason);
#endif

#if !defined(WIN32) || defined(WIN64)
typedef void (*SetSteamIDFunc)(CBaseClient *, const CSteamID &steamID);
#else
typedef void (__fastcall *SetSteamIDFunc)(CBaseClient *, void *, const CSteamID &steamID);
#endif

#ifndef WIN32
typedef int (*NET_SendPacketFunc)(INetChannel * chan, int sock, const netadr_t & to, const unsigned char * data, int length, bf_write * pVoicePayload, bool bUseCompression);
#else
typedef int (__fastcall *NET_SendPacketFunc)(INetChannel * chan, int sock, const netadr_t & to, const unsigned char * data, int length, bf_write * pVoicePayload, bool bUseCompression);
#endif

#ifndef WIN32
typedef void (*NET_CheckCleanupFakeIPConnectionFunc)(int iClientChallenge, const netadr_t & address);
#else
typedef void (__fastcall *NET_CheckCleanupFakeIPConnectionFunc)(int iClientChallenge, const netadr_t & address);
#endif

CDetour* detourCBaseServer__ConnectClient = nullptr;
CDetour* detourCBaseServer__RejectConnection = nullptr;

bool g_bEndAuthSessionOnRejectConnection = false;
bool g_bSuppressBeginAuthSession = false;
CSteamID g_lastClientSteamID;
const void* g_lastAuthTicket;
int g_lastcbAuthTicket;

char passwordBuffer[255];

Steam3ServerFunc g_pSteam3ServerFunc = NULL;
RejectConnectionFunc g_pRejectConnectionFunc = NULL;
SetSteamIDFunc g_pSetSteamIDFunc = NULL;
#if SOURCE_ENGINE != SE_LEFT4DEAD && SOURCE_ENGINE != SE_LEFT4DEAD2
NET_SendPacketFunc g_pNET_SendPacketFunc = NULL;
NET_CheckCleanupFakeIPConnectionFunc g_pNET_CheckCleanupFakeIPConnectionFunc = NULL;
#endif

CSteam3Server *Steam3Server()
{
	if (!g_pSteam3ServerFunc)
		return NULL;

	return g_pSteam3ServerFunc();
}

void RejectConnection(const netadr_t &address, int iClientChallenge, const char *pchReason)
{
	if (!g_pRejectConnectionFunc || !g_pBaseServer)
		return;

#if !defined(WIN32) || defined(WIN64)
	g_pRejectConnectionFunc(g_pBaseServer, address, iClientChallenge, pchReason);
#else
	g_pRejectConnectionFunc(g_pBaseServer, NULL, address, iClientChallenge, pchReason);
#endif
}

void SetSteamID(CBaseClient *pClient, const CSteamID &steamID)
{
	if (!pClient || !g_pSetSteamIDFunc)
		return;

#if !defined(WIN32) || defined(WIN64)
	g_pSetSteamIDFunc(pClient, steamID);
#else
	g_pSetSteamIDFunc(pClient, NULL, steamID);
#endif
}

class VFuncEmptyClass{};

int g_nBeginAuthSessionOffset = 0;
int g_nEndAuthSessionOffset = 0;

SH_DECL_MANUALHOOK3(MHook_BeginAuthSession, 0, 0, 0, EBeginAuthSessionResult, const void *, int, CSteamID);
int g_nHookIdBeginAuthSession = -1;

EBeginAuthSessionResult Hook_BeginAuthSession(const void *pAuthTicket, int cbAuthTicket, CSteamID steamID)
{
	if (!g_bSuppressBeginAuthSession)
	{
		RETURN_META_VALUE(MRES_IGNORED, k_EBeginAuthSessionResultOK);
	}
	g_bSuppressBeginAuthSession = false;

	if (strcmp(steamID.Render(), g_lastClientSteamID.Render()) == 0
	&& g_lastAuthTicket == pAuthTicket
	&& g_lastcbAuthTicket == cbAuthTicket)
	{
		// Let the server know everything is fine
		// g_pSM->LogMessage(myself, "You alright ;)");
		RETURN_META_VALUE(MRES_SUPERCEDE, k_EBeginAuthSessionResultOK);
	}

	RETURN_META_VALUE(MRES_IGNORED, k_EBeginAuthSessionResultDuplicateRequest);
}

EBeginAuthSessionResult BeginAuthSession(const void *pAuthTicket, int cbAuthTicket, CSteamID steamID)
{
	if (g_nBeginAuthSessionOffset == 0)
		return k_EBeginAuthSessionResultInvalidTicket;

	void *func = (*(void ***)g_pSteam3Server->m_pSteamGameServer)[g_nBeginAuthSessionOffset];

	union {
		EBeginAuthSessionResult (VFuncEmptyClass::*mfpnew)(const void *, int, CSteamID);
		mfpDetails mfp;
	} u;
	u.mfp.Init(func);

	return (EBeginAuthSessionResult)(reinterpret_cast<VFuncEmptyClass*>(g_pSteam3Server->m_pSteamGameServer)->*u.mfpnew)(pAuthTicket, cbAuthTicket, steamID);
}

void EndAuthSession(CSteamID steamID)
{
	if (g_nEndAuthSessionOffset == 0)
		return;

	void *func = (*(void ***)g_pSteam3Server->m_pSteamGameServer)[g_nEndAuthSessionOffset];

	union {
		void (VFuncEmptyClass::*mfpnew)(CSteamID);
		mfpDetails mfp;
	} u;
	u.mfp.Init(func);

	return (void)(reinterpret_cast<VFuncEmptyClass*>(g_pSteam3Server->m_pSteamGameServer)->*u.mfpnew)(steamID);
}

DETOUR_DECL_MEMBER9(CBaseServer__ConnectClient, IClient*, netadr_t&, address, int, nProtocol, int, iChallenge, int, iClientChallenge, int, nAuthProtocol, const char *, pchName, const char *, pchPassword, const char *, pCookie, int, cbCookie)
{
	if (nAuthProtocol != k_EAuthProtocolSteam)
	{
		// This is likely a SourceTV client, we don't want to interfere here.
		return DETOUR_MEMBER_CALL(CBaseServer__ConnectClient)(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, pCookie, cbCookie);
	}

	g_pBaseServer = (CBaseServer *)this;

	if (pCookie == NULL || (size_t)cbCookie < sizeof(uint64))
	{
		RejectConnection(address, iClientChallenge, "#GameUI_ServerRejectInvalidSteamCertLen");
		return NULL;
	}

	char ipString[30];
	V_snprintf(ipString, sizeof(ipString), "%u.%u.%u.%u", address.ip[0], address.ip[1], address.ip[2], address.ip[3]);
	V_strncpy(passwordBuffer, pchPassword, 255);
	uint64 ullSteamID = *(uint64 *)pCookie;

	void *pvTicket = (void *)((intptr_t)pCookie + sizeof(uint64));
	int cbTicket = cbCookie - sizeof(uint64);

	g_bEndAuthSessionOnRejectConnection = true;
	g_lastClientSteamID = CSteamID(ullSteamID);
	g_lastcbAuthTicket = cbTicket;
	g_lastAuthTicket = pvTicket;

	// Validate steam ticket
	EBeginAuthSessionResult result = BeginAuthSession(pvTicket, cbTicket, g_lastClientSteamID);
	if (result != k_EBeginAuthSessionResultOK)
	{
		RejectConnection(address, iClientChallenge, "#GameUI_ServerRejectSteam");
		return NULL;
	}

	char rejectReason[255];

	g_pConnectForward->PushString(pchName);
	g_pConnectForward->PushStringEx(passwordBuffer, 255, SM_PARAM_STRING_UTF8 | SM_PARAM_STRING_COPY, SM_PARAM_COPYBACK);
	g_pConnectForward->PushString(ipString);
	g_pConnectForward->PushString(g_lastClientSteamID.Render());
	g_pConnectForward->PushStringEx(rejectReason, 255, SM_PARAM_STRING_UTF8 | SM_PARAM_STRING_COPY, SM_PARAM_COPYBACK);

	cell_t retVal = 1;
	g_pConnectForward->Execute(&retVal);

	if (retVal == 0)
	{
		RejectConnection(address, iClientChallenge, rejectReason);
		return NULL;
	}

	pchPassword = passwordBuffer;

	g_bSuppressBeginAuthSession = true;
	auto client = DETOUR_MEMBER_CALL(CBaseServer__ConnectClient)(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, pCookie, cbCookie);
	g_bSuppressBeginAuthSession = false;
	return client;
}

DETOUR_DECL_MEMBER3(CBaseServer__RejectConnection, void, netadr_t &, address, int, iClientChallenge, const char *, pchReason)
{
	if (g_bEndAuthSessionOnRejectConnection)
	{
		EndAuthSession(g_lastClientSteamID);
		g_bEndAuthSessionOnRejectConnection = false;
	}

#if SOURCE_ENGINE == SE_LEFT4DEAD || SOURCE_ENGINE == SE_LEFT4DEAD2
	DETOUR_MEMBER_CALL(CBaseServer__RejectConnection)(address, iClientChallenge, pchReason);
#else
	ALIGN4 char	msg_buffer[MAX_ROUTABLE_PAYLOAD] ALIGN4_POST;
	bf_write	msg(msg_buffer, sizeof(msg_buffer));

	msg.WriteLong(CONNECTIONLESS_HEADER);
	msg.WriteByte(S2C_CONNREJECT);
	msg.WriteLong(iClientChallenge);
	msg.WriteString(pchReason);

	g_pNET_SendPacketFunc(NULL, NS_SERVER, address, msg.GetData(), msg.GetNumBytesWritten(), NULL, false);
	g_pNET_CheckCleanupFakeIPConnectionFunc(NS_SERVER, address);
#endif
	return;
}

bool Connect::SDK_OnLoad(char *error, size_t maxlen, bool late)
{
	char conf_error[255] = "";
	if (!gameconfs->LoadGameConfigFile("connect.games", &g_pGameConf, conf_error, sizeof(conf_error)))
	{
		if (conf_error[0])
		{
			snprintf(error, maxlen, "Could not read connect.games.txt: %s\n", conf_error);
		}
		return false;
	}

	if (!g_pGameConf->GetMemSig("CBaseServer__RejectConnection", (void **)(&g_pRejectConnectionFunc)) || !g_pRejectConnectionFunc)
	{
		snprintf(error, maxlen, "Failed to find CBaseServer__RejectConnection function.\n");
		return false;
	}

#if SOURCE_ENGINE != SE_LEFT4DEAD && SOURCE_ENGINE != SE_LEFT4DEAD2
	if (!g_pGameConf->GetMemSig("NET_SendPacket", (void **)(&g_pNET_SendPacketFunc)) || !g_pNET_SendPacketFunc)
	{
		snprintf(error, maxlen, "Failed to find NET_SendPacket function.\n");
		return false;
	}

	if (!g_pGameConf->GetMemSig("NET_CheckCleanupFakeIPConnection", (void **)(&g_pNET_CheckCleanupFakeIPConnectionFunc)) || !g_pNET_CheckCleanupFakeIPConnectionFunc)
	{
		snprintf(error, maxlen, "Failed to find NET_CheckCleanupFakeIPConnection function.\n");
		return false;
	}
#endif

	if (!g_pGameConf->GetMemSig("CBaseClient__SetSteamID", (void **)(&g_pSetSteamIDFunc)) || !g_pSetSteamIDFunc)
	{
		snprintf(error, maxlen, "Failed to find CBaseClient__SetSteamID function.\n");
		return false;
	}

#ifndef WIN32
	if (!g_pGameConf->GetMemSig("Steam3Server", (void **)(&g_pSteam3ServerFunc)) || !g_pSteam3ServerFunc)
	{
		snprintf(error, maxlen, "Failed to find Steam3Server function.\n");
		return false;
	}
#else
	void *address;
	if (!g_pGameConf->GetMemSig("CBaseServer__CheckMasterServerRequestRestart", &address) || !address)
	{
		snprintf(error, maxlen, "Failed to find CBaseServer__CheckMasterServerRequestRestart function.\n");
		return false;
	}

	int steam3ServerFuncOffset = 0;
	if (!g_pGameConf->GetOffset("CheckMasterServerRequestRestart_Steam3ServerFuncOffset", &steam3ServerFuncOffset) || steam3ServerFuncOffset == 0)
	{
		snprintf(error, maxlen, "Failed to find CheckMasterServerRequestRestart_Steam3ServerFuncOffset offset.\n");
		return false;
	}

	//META_CONPRINTF("CheckMasterServerRequestRestart: %p\n", address);
	address = (void *)((intptr_t)address + steam3ServerFuncOffset);
	int32_t offset = (*(int32_t *)address); // Get offset (yes, int32 even on 64-bit)

	g_pSteam3ServerFunc = (Steam3ServerFunc)((intptr_t)address + offset + sizeof(int32_t));
	//META_CONPRINTF("Steam3Server: %p\n", g_pSteam3ServerFunc);
#endif

	g_pSteam3Server = Steam3Server();
	if (!g_pSteam3Server)
	{
		snprintf(error, maxlen, "Unable to get Steam3Server singleton.\n");
		return false;
	}

	if (!g_pSteam3Server->m_pSteamGameServer)
	{
		snprintf(error, maxlen, "Unable to get Steam Game Server.\n");
		return false;
	}

	/*
	META_CONPRINTF("ISteamGameServer: %p\n", g_pSteam3Server->m_pSteamGameServer);
	META_CONPRINTF("ISteamUtils: %p\n", g_pSteam3Server->m_pSteamGameServerUtils);
	META_CONPRINTF("ISteamMasterServerUpdater: %p\n", g_pSteam3Server->m_pSteamMasterServerUpdater);
	META_CONPRINTF("ISteamNetworking: %p\n", g_pSteam3Server->m_pSteamGameServerNetworking);
	META_CONPRINTF("ISteamGameServerStats: %p\n", g_pSteam3Server->m_pSteamGameServerStats);
	*/

	if (!g_pGameConf->GetOffset("ISteamGameServer__BeginAuthSession", &g_nBeginAuthSessionOffset) || g_nBeginAuthSessionOffset == 0)
	{
		snprintf(error, maxlen, "Failed to find ISteamGameServer__BeginAuthSession offset.\n");
		return false;
	}
	SH_MANUALHOOK_RECONFIGURE(MHook_BeginAuthSession, g_nBeginAuthSessionOffset, 0, 0);
	if (SH_ADD_MANUALHOOK(MHook_BeginAuthSession, g_pSteam3Server->m_pSteamGameServer, SH_STATIC(Hook_BeginAuthSession), true) == 0)
	{
		snprintf(error, maxlen, "Failed to setup ISteamGameServer__BeginAuthSession hook.\n");
		return false;
	}

	if (!g_pGameConf->GetOffset("ISteamGameServer__EndAuthSession", &g_nEndAuthSessionOffset) || g_nEndAuthSessionOffset == 0)
	{
		snprintf(error, maxlen, "Failed to find ISteamGameServer__EndAuthSession offset.\n");
		return false;
	}

	CDetourManager::Init(g_pSM->GetScriptingEngine(), g_pGameConf);

	detourCBaseServer__ConnectClient = DETOUR_CREATE_MEMBER(CBaseServer__ConnectClient, "CBaseServer__ConnectClient");
	if (detourCBaseServer__ConnectClient == nullptr)
	{
		snprintf(error, maxlen, "Failed to create CBaseServer__ConnectClient detour.\n");
		return false;
	}
	detourCBaseServer__ConnectClient->EnableDetour();

	detourCBaseServer__RejectConnection = DETOUR_CREATE_MEMBER(CBaseServer__RejectConnection, "CBaseServer__RejectConnection");
	if (detourCBaseServer__RejectConnection == nullptr)
	{
		snprintf(error, maxlen, "Failed to create CBaseServer__RejectConnection detour.\n");
		return false;
	}
	detourCBaseServer__RejectConnection->EnableDetour();

	g_pConnectForward = g_pForwards->CreateForward("OnClientPreConnectEx", ET_LowEvent, 5, NULL, Param_String, Param_String, Param_String, Param_String, Param_String);

	return true;
}

bool Connect::SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late)
{
	GET_V_IFACE_CURRENT(GetEngineFactory, g_pCVar, ICvar, CVAR_INTERFACE_VERSION);

	ConVar_Register(0, this);

	return true;
}

void Connect::SDK_OnUnload() 
{
	g_pForwards->ReleaseForward(g_pConnectForward);

	gameconfs->CloseGameConfigFile(g_pGameConf);
}

bool Connect::SDK_OnMetamodUnload(char *error, size_t maxlen)
{
	if (detourCBaseServer__ConnectClient)
	{
		detourCBaseServer__ConnectClient->DisableDetour();
		delete detourCBaseServer__ConnectClient;
	}

	if (detourCBaseServer__RejectConnection)
	{
		detourCBaseServer__RejectConnection->DisableDetour();
		delete detourCBaseServer__RejectConnection;
	}

	return true;
}

bool Connect::RegisterConCommandBase(ConCommandBase *pCommand)
{
	META_REGCVAR(pCommand);

	return true;
}
