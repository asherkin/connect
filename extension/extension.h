/**
 * =============================================================================
 * TF2 Items Extension
 * Copyright (C) 2009-2010 AzuiSleet, Asher Baker (asherkin).  All rights reserved.
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
 */

#ifndef _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_
#define _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_

/**
 * @file extension.hpp
 * @brief Connect extension code header.
 */

#include "smsdk_ext.h"

/**
 * @brief Sample implementation of the SDK Extension.
 * Note: Uncomment one of the pre-defined virtual functions in order to use it.
 */
class Connect : public SDKExtension, public IConCommandBaseAccessor
{
public:
	/**
	 * @brief This is called after the initial loading sequence has been processed.
	 *
	 * @param error		Error message buffer.
	 * @param maxlength	Size of error message buffer.
	 * @param late		Whether or not the module was loaded after map load.
	 * @return			True to succeed loading, false to fail.
	 */
	virtual bool SDK_OnLoad(char *error, size_t maxlen, bool late);
	
	/**
	 * @brief This is called right before the extension is unloaded.
	 */
	virtual void SDK_OnUnload();

	/**
	 * @brief This is called once all known extensions have been loaded.
	 * Note: It is is a good idea to add natives here, if any are provided.
	 */
	virtual void SDK_OnAllLoaded();

	/**
	 * @brief Called when the pause state is changed.
	 */
	//virtual void SDK_OnPauseChange(bool paused);

	/**
	 * @brief this is called when Core wants to know if your extension is working.
	 *
	 * @param error		Error message buffer.
	 * @param maxlength	Size of error message buffer.
	 * @return			True if working, false otherwise.
	 */
	//virtual bool QueryRunning(char *error, size_t maxlen);
public:
#if defined SMEXT_CONF_METAMOD
	/**
	 * @brief Called when Metamod is attached, before the extension version is called.
	 *
	 * @param error			Error buffer.
	 * @param maxlength		Maximum size of error buffer.
	 * @param late			Whether or not Metamod considers this a late load.
	 * @return				True to succeed, false to fail.
	 */
	virtual bool SDK_OnMetamodLoad(ISmmAPI *ismm, char *error, size_t maxlen, bool late);

	/**
	 * @brief Called when Metamod is detaching, after the extension version is called.
	 * NOTE: By default this is blocked unless sent from SourceMod.
	 *
	 * @param error			Error buffer.
	 * @param maxlength		Maximum size of error buffer.
	 * @return				True to succeed, false to fail.
	 */
	virtual bool SDK_OnMetamodUnload(char *error, size_t maxlen);

	/**
	 * @brief Called when Metamod's pause state is changing.
	 * NOTE: By default this is blocked unless sent from SourceMod.
	 *
	 * @param paused		Pause state being set.
	 * @param error			Error buffer.
	 * @param maxlength		Maximum size of error buffer.
	 * @return				True to succeed, false to fail.
	 */
	//virtual bool SDK_OnMetamodPauseChange(bool paused, char *error, size_t maxlen);
#endif
public: //IConCommandBaseAccessor
	bool RegisterConCommandBase(ConCommandBase *pCommand);
};

#define DETOUR_MEMBER_MCALL_CALLBACK(name, classptr) \
	((name##Class *)classptr->*(&name##Class::name))
#define DETOUR_MEMBER_MCALL_ORIGINAL(name, classptr) \
	((name##Class *)classptr->*(name##Class::name##_Actual))

#define DETOUR_DECL_MEMBER9(name, ret, p1type, p1name, p2type, p2name, p3type, p3name, p4type, p4name, p5type, p5name, p6type, p6name, p7type, p7name, p8type, p8name, p9type, p9name) \
class name##Class \
{ \
public: \
        ret name(p1type p1name, p2type p2name, p3type p3name, p4type p4name, p5type p5name, p6type p6name, p7type p7name, p8type p8name, p9type p9name); \
        static ret (name##Class::* name##_Actual)(p1type, p2type, p3type, p4type, p5type, p6type, p7type, p8type, p9type); \
}; \
ret (name##Class::* name##Class::name##_Actual)(p1type, p2type, p3type, p4type, p5type, p6type, p7type, p8type, p9type) = NULL; \
ret name##Class::name(p1type p1name, p2type p2name, p3type p3name, p4type p4name, p5type p5name, p6type p6name, p7type p7name, p8type p8name, p9type p9name)

struct mfpDetails {
	void *addr;
	intptr_t adjustor;

	void Init(void* addr, intptr_t adj = 0) {
		this->addr = addr;
		this->adjustor = adj;
	}
};

#endif // _INCLUDE_SOURCEMOD_EXTENSION_PROPER_H_
