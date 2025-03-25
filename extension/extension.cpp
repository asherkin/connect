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
#include <string>

Connect g_connect;

SMEXT_LINK(&g_connect);

ConVar connectVersion("connect_version", SMEXT_CONF_VERSION, FCVAR_SPONLY|FCVAR_REPLICATED|FCVAR_NOTIFY, SMEXT_CONF_DESCRIPTION " Version");

IGameConfig *g_pGameConf = NULL;
IForward *g_pConnectForward = NULL;

class IClient;
class CBaseServer;

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

const char *CSteamID::Render() const
{
	static char szSteamID[64];
	V_snprintf(szSteamID, sizeof(szSteamID), "STEAM_0:%u:%u", this->GetAccountID() & 1, this->GetAccountID() >> 1);
	return szSteamID;
}

class ISteamGameServer;
class CSteam3Server
{
public:
	void *m_pSteamClient;
	ISteamGameServer* m_pSteamGameServer;
	void *m_pSteamGameServerUtils;
	void *m_pSteamGameServerNetworking;
	void *m_pSteamGameServerStats;
	void *m_pSteamHTTP;
	void *m_pSteamInventory;
	void *m_pSteamUGC;
	void *m_pSteamApps;
} *g_pSteam3Server;

typedef CSteam3Server *(*Steam3ServerFunc)();

class FEmptyClass {};
template<typename classcall, typename RetType, typename... Args>
union MFPHack {
private:
	void* addr;
public:
	MFPHack(void* addr)
	{
		this->addr = addr;
	}

	template<typename randomclass>
	MFPHack(RetType (randomclass::*mfp)(Args...))
	{
		union
		{
			RetType (randomclass::*ptr)(Args...);
			struct
			{
				void* addr;
#ifdef __linux__
				intptr_t adjustor;
#endif
			} details;
		} u;
		u.ptr = mfp;
		this->addr = u.details.addr;
	}

	void SetAddress(void* addr)
	{
		this->addr = addr;
	}

	void* GetAddress()
	{
		return this->addr;
	}

	RetType operator()(classcall* ptrThis, Args... args)
	{
		union
		{
			RetType (FEmptyClass::*ptr)(Args...);
			struct
			{
				void* addr;
#ifdef __linux__
				intptr_t adjustor;
#endif
			} details;
		} u;

		u.details.addr = addr;
#ifdef __linux__
		u.details.adjustor = 0;
#endif
		return (((FEmptyClass*)ptrThis)->*u.ptr)(args...);
	}
};

CDetour* detourCBaseServer__ConnectClient = nullptr;
bool g_bEndAuthSessionOnRejectConnection = false;
bool g_bSuppressBeginAuthSession = false;
CSteamID g_lastClientSteamID;
const void* g_lastAuthTicket;
int g_lastcbAuthTicket;

char passwordBuffer[255];

Steam3ServerFunc g_pSteam3ServerFunc = nullptr;
MFPHack<CBaseServer, void, const netadr_t &, int, const char *> g_pRejectConnectionFunc(nullptr);
MFPHack<ISteamGameServer, EBeginAuthSessionResult, const void*, int, CSteamID> g_pBeginAuthSession(nullptr);
MFPHack<ISteamGameServer, void, CSteamID> g_pEndAuthSession(nullptr);

CSteam3Server *Steam3Server()
{
	if (!g_pSteam3ServerFunc)
		return NULL;

	return g_pSteam3ServerFunc();
}

SH_DECL_MANUALHOOK3(MHook_BeginAuthSession, 0, 0, 0, EBeginAuthSessionResult, const void *, int, CSteamID);
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

DETOUR_DECL_MEMBER9(CBaseServer__ConnectClient, IClient*, netadr_t&, address, int, nProtocol, int, iChallenge, int, iClientChallenge, int, nAuthProtocol, const char *, pchName, const char *, pchPassword, const char *, pCookie, int, cbCookie)
{
	if (nAuthProtocol != k_EAuthProtocolSteam)
	{
		// This is likely a SourceTV client, we don't want to interfere here.
		return DETOUR_MEMBER_CALL(CBaseServer__ConnectClient)(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, pCookie, cbCookie);
	}

	if (pCookie == NULL || (size_t)cbCookie < sizeof(uint64))
	{
		g_pRejectConnectionFunc((CBaseServer*)this, address, iClientChallenge, "#GameUI_ServerRejectInvalidSteamCertLen");
		return NULL;
	}

	auto steamGameServer = Steam3Server()->m_pSteamGameServer;

	char ipString[30];
	V_snprintf(ipString, sizeof(ipString), "%u.%u.%u.%u", address.ip[0], address.ip[1], address.ip[2], address.ip[3]);
	V_strncpy(passwordBuffer, pchPassword, 255);
	uint64 ullSteamID = *(uint64 *)pCookie;

	void *pvTicket = (void *)((intptr_t)pCookie + sizeof(uint64));
	int cbTicket = cbCookie - sizeof(uint64);

	g_lastClientSteamID = CSteamID(ullSteamID);
	g_lastcbAuthTicket = cbTicket;
	g_lastAuthTicket = pvTicket;

	// Validate steam ticket
	EBeginAuthSessionResult result = g_pBeginAuthSession(steamGameServer, pvTicket, cbTicket, g_lastClientSteamID);
	if (result != k_EBeginAuthSessionResultOK)
	{
		g_pRejectConnectionFunc((CBaseServer*)this, address, iClientChallenge, "#GameUI_ServerRejectSteam");
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
		g_pEndAuthSession(steamGameServer, g_lastClientSteamID);
		g_pRejectConnectionFunc((CBaseServer*)this, address, iClientChallenge, rejectReason);
		return NULL;
	}

	pchPassword = passwordBuffer;

	g_bSuppressBeginAuthSession = true;
	auto client = DETOUR_MEMBER_CALL(CBaseServer__ConnectClient)(address, nProtocol, iChallenge, iClientChallenge, nAuthProtocol, pchName, pchPassword, pCookie, cbCookie);
	g_bSuppressBeginAuthSession = false;
	if (client == nullptr)
	{
		g_pEndAuthSession(steamGameServer, g_lastClientSteamID);
	}
	return client;
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

	void* addr;
	if (!g_pGameConf->GetMemSig("CBaseServer__RejectConnection", &addr) || addr == nullptr)
	{
		snprintf(error, maxlen, "Failed to find CBaseServer__RejectConnection function.\n");
		return false;
	}
	g_pRejectConnectionFunc.SetAddress(addr);

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
	g_pSteam3ServerFunc = (Steam3ServerFunc)((intptr_t)address + *((int32_t *)address) + sizeof(int32_t));
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
	void** vtable = *((void***)g_pSteam3Server->m_pSteamGameServer);

	int offset = 0;
	if (!g_pGameConf->GetOffset("ISteamGameServer__BeginAuthSession", &offset) || offset == 0)
	{
		snprintf(error, maxlen, "Failed to find ISteamGameServer__BeginAuthSession offset.\n");
		return false;
	}
	g_pBeginAuthSession.SetAddress(vtable[offset]);

	offset = 0;
	if (!g_pGameConf->GetOffset("ISteamGameServer__EndAuthSession", &offset) || offset == 0)
	{
		snprintf(error, maxlen, "Failed to find ISteamGameServer__EndAuthSession offset.\n");
		return false;
	}
	g_pEndAuthSession.SetAddress(vtable[offset]);

	SH_MANUALHOOK_RECONFIGURE(MHook_BeginAuthSession, offset, 0, 0);
	if (SH_ADD_MANUALHOOK(MHook_BeginAuthSession, g_pSteam3Server->m_pSteamGameServer, SH_STATIC(Hook_BeginAuthSession), true) == 0)
	{
		snprintf(error, maxlen, "Failed to setup ISteamGameServer__BeginAuthSession hook.\n");
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

	return true;
}

bool Connect::RegisterConCommandBase(ConCommandBase *pCommand)
{
	META_REGCVAR(pCommand);

	return true;
}
