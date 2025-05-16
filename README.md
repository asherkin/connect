# Connect - A safer OnClientPreConnect forward

This extension provides a OnClientPreConnect forward (similar to CBaseServer's), but does proper checking to prevent malicious people spoofing SteamIDs.

If you are currently using CBaseServer for reserved slots, it's possible for a client to spoof an admin's SteamID and cause someone to be kicked from the server (although they would be later denied, so they couldn't actually join the game).
This extension does these checks before OnClientPreConnect is fired, so this isn't possible.

There are some additional features such as being able to change the password provided before it's checked (see included example plugin) and the ability to reject the client with a reason (like SourceMod's later OnClientConnect forward).

Only the Source 2009 engine is supported, as it's the only one that's been updated to use the new authentication system.

# Provided forwards

```
public bool OnClientPreConnectEx
(
  const char[] name,
  char password[255],
  const char[] ip,
  const char[] steamID,
  char rejectReason[255]
)
{
    // ...
}
```

`return false;` to disallow the client from joining, and change `rejectReason` to what you want them to be shown when denied.

Note that this function is called before the client has a client index on the server.
