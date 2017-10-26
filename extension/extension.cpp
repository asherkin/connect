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

#include "extension.hpp"
#include "CDetour/detours.h"

#include "steam/steamclientpublic.h"

Connect g_connect;

SMEXT_LINK(&g_connect);

ConVar connectVersion("connect_version", SMEXT_CONF_VERSION, FCVAR_SPONLY|FCVAR_REPLICATED|FCVAR_NOTIFY, SMEXT_CONF_DESCRIPTION " Version");

IGameConfig *g_pGameConf = NULL;

IForward *g_pConnectForward = NULL;

class IClient;
class CBaseClient;

class CBaseServer;

typedef enum EAuthProtocol
{
	k_EAuthProtocolWONCertificate = 1,
	k_EAuthProtocolHashedCDKey = 2,
	k_EAuthProtocolSteam = 3,
} EAuthProtocol;

typedef enum EBeginAuthSessionResult
{
	k_EBeginAuthSessionResultOK = 0,				// Ticket is valid for this game and this steamID.
	k_EBeginAuthSessionResultInvalidTicket = 1,		// Ticket is not valid.
	k_EBeginAuthSessionResultDuplicateRequest = 2,	// A ticket has already been submitted for this steamID
	k_EBeginAuthSessionResultInvalidVersion = 3,	// Ticket is from an incompatible interface version
	k_EBeginAuthSessionResultGameMismatch = 4,		// Ticket is not for this game
	k_EBeginAuthSessionResultExpiredTicket = 5,		// Ticket has expired
} EBeginAuthSessionResult;

typedef struct netadr_s
{
private:
	typedef enum
	{ 
		NA_NULL = 0,
		NA_LOOPBACK,
		NA_BROADCAST,
		NA_IP,
	} netadrtype_t;

public:
	netadrtype_t	type;
	unsigned char	ip[4];
	unsigned short	port;
} netadr_t;

char *CSteamID::Render() const
{
	static char szSteamID[64];
	V_snprintf(szSteamID, sizeof(szSteamID), "STEAM_0:%u:%u", (m_unAccountID % 2) ? 1 : 0, (int32)m_unAccountID/2);
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
	if (!g_pSteam3ServerFunc)
		return NULL;

	return g_pSteam3ServerFunc();
}

void RejectConnection(const netadr_t &address, int iClientChallenge, const char *pchReason)
{
	if (!g_pRejectConnectionFunc || !g_pBaseServer)
		return;

#ifndef WIN32
	g_pRejectConnectionFunc(g_pBaseServer, address, iClientChallenge, pchReason);
#else
	g_pRejectConnectionFunc(g_pBaseServer, NULL, address, iClientChallenge, pchReason);
#endif
}

void SetSteamID(CBaseClient *pClient, const CSteamID &steamID)
{
	if (!pClient || !g_pSetSteamIDFunc)
		return;

#ifndef WIN32
	g_pSetSteamIDFunc(pClient, steamID);
#else
	g_pSetSteamIDFunc(pClient, NULL, steamID);
#endif
}

class VFuncEmptyClass{};

int g_nBeginAuthSessionOffset = 0;
int g_nEndAuthSessionOffset = 0;

EBeginAuthSessionResult BeginAuthSession(const void *pAuthTicket, int cbAuthTicket, CSteamID steamID)
{
	if (!g_pSteam3Server || !g_pSteam3Server->m_pSteamGameServer || g_nBeginAuthSessionOffset == 0)
		return k_EBeginAuthSessionResultOK;

	void **this_ptr = *(void ***)&g_pSteam3Server->m_pSteamGameServer;
	void **vtable = *(void ***)g_pSteam3Server->m_pSteamGameServer;
	void *func = vtable[g_nBeginAuthSessionOffset];

	union {
		EBeginAuthSessionResult (VFuncEmptyClass::*mfpnew)(const void *, int, CSteamID);

#ifndef WIN32
		struct {
			void *addr;
			intptr_t adjustor;
		} s;
	} u;

	u.s.addr = func;
	u.s.adjustor = 0;
#else
		void *addr;
	} u;

	u.addr = func;
#endif

	return (EBeginAuthSessionResult)(reinterpret_cast<VFuncEmptyClass*>(this_ptr)->*u.mfpnew)(pAuthTicket, cbAuthTicket, steamID);
}

void EndAuthSession(CSteamID steamID)
{
	if (!g_pSteam3Server || !g_pSteam3Server->m_pSteamGameServer || g_nEndAuthSessionOffset == 0)
		return;

	void **this_ptr = *(void ***)&g_pSteam3Server->m_pSteamGameServer;
	void **vtable = *(void ***)g_pSteam3Server->m_pSteamGameServer;
	void *func = vtable[g_nEndAuthSessionOffset];

	union {
		void (VFuncEmptyClass::*mfpnew)(CSteamID);

#ifndef WIN32
		struct {
			void *addr;
			intptr_t adjustor;
		} s;
	} u;

	u.s.addr = func;
	u.s.adjustor = 0;
#else
		void *addr;
	} u;

	u.addr = func;
#endif

	return (void)(reinterpret_cast<VFuncEmptyClass*>(this_ptr)->*u.mfpnew)(steamID);
}

DECL_DETOUR(CBaseServer__ConnectClient);
DECL_DETOUR(CBaseServer__RejectConnection)
DECL_DETOUR(CBaseServer__CheckChallengeType);

bool g_bEndAuthSessionOnRejectConnection = false;
CSteamID g_lastClientSteamID;

bool g_bSuppressCheckChallengeType = false;

char passwordBuffer[255];
DETOUR_DECL_MEMBER9(CBaseServer__ConnectClient, IClient *, netadr_t &, address, int, nProtocol, int, iChallenge, int, iClientChallenge, int, nAuthProtocol, const char *, pchName, const char *, pchPassword, const char *, pCookie, int, cbCookie)
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

	g_bSuppressCheckChallengeType = true;
	return DETOUR_MEMBER_CALL(CBaseServer__ConnectClient)(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, pCookie, cbCookie);
}

DETOUR_DECL_MEMBER3(CBaseServer__RejectConnection, void, netadr_t &, address, int, iClientChallenge, const char *, pchReason)
{
	if (g_bEndAuthSessionOnRejectConnection)
	{
		EndAuthSession(g_lastClientSteamID);
		g_bEndAuthSessionOnRejectConnection = false;
	}

	return DETOUR_MEMBER_CALL(CBaseServer__RejectConnection)(address, iClientChallenge, pchReason);
}

DETOUR_DECL_MEMBER7(CBaseServer__CheckChallengeType, bool, CBaseClient *, pClient, int, nUserID, netadr_t &, address, int, nAuthProtocol, const char *, pCookie, int, cbCookie, int, iClientChallenge)
{
	if (g_bSuppressCheckChallengeType)
	{
		g_bEndAuthSessionOnRejectConnection = false;

		SetSteamID(pClient, g_lastClientSteamID);

		g_bSuppressCheckChallengeType = false;
		return true;
	} else {
		return DETOUR_MEMBER_CALL(CBaseServer__CheckChallengeType)(pClient, nUserID, address, nAuthProtocol, pCookie, cbCookie, iClientChallenge);
	}
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

	//META_CONPRINTF("CheckMasterServerRequestRestart: %p\n", address);
	address = (void *)((intptr_t)address + 1); // Skip CALL opcode
	intptr_t offset = (intptr_t)(*(void **)address); // Get offset

	g_pSteam3ServerFunc = (Steam3ServerFunc)((intptr_t)address + offset + sizeof(intptr_t));
	//META_CONPRINTF("Steam3Server: %p\n", g_pSteam3ServerFunc);
#endif

	g_pSteam3Server = Steam3Server();
	if (!g_pSteam3Server)
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

	if (!g_pGameConf->GetOffset("ISteamGameServer__BeginAuthSession", &g_nBeginAuthSessionOffset) || g_nBeginAuthSessionOffset == 0)
	{
		snprintf(error, maxlen, "Failed to find ISteamGameServer__BeginAuthSession offset.\n");
		return false;
	}

	if (!g_pGameConf->GetOffset("ISteamGameServer__EndAuthSession", &g_nEndAuthSessionOffset) || g_nEndAuthSessionOffset == 0)
	{
		snprintf(error, maxlen, "Failed to find ISteamGameServer__EndAuthSession offset.\n");
		return false;
	}

	CDetourManager::Init(g_pSM->GetScriptingEngine(), g_pGameConf);

	CREATE_DETOUR(CBaseServer__ConnectClient);
	CREATE_DETOUR(CBaseServer__RejectConnection);
	CREATE_DETOUR(CBaseServer__CheckChallengeType);

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
	DESTROY_DETOUR(CBaseServer__ConnectClient);
	DESTROY_DETOUR(CBaseServer__RejectConnection);
	DESTROY_DETOUR(CBaseServer__CheckChallengeType);

	return true;
}

bool Connect::RegisterConCommandBase(ConCommandBase *pCommand)
{
	META_REGCVAR(pCommand);

	return true;
}
