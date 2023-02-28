from IPInfo import getIP

def formatMastodonHook(data):
    event = data['event']
    if event.startswith('account.'):
        account = data['object']
        username = account['username']
        if event == 'account.created':
            email = account['email']
            ip = account['ip']
            country = getIP(ip)
            reason = account['invite_request']
            return(
                f"## New account created  \n"
                f"**User:** `{username}`  \n"
                f"**Email:** `{email}`  \n"
                f"**IP:** `{ip}` *({country})* [More info at IPinfo.io](https://ipinfo.io/{ip})  \n"
                f"**Reason:**  \n"
                f"> {reason}"
                )
        if event == 'account.approved':
            return(
                f"## New account approved  \n"
                f"**User:** `{username}`"
                )
    else:
        import json
        return "```\n"+json.dumps(data, indent=2)+"\n```"
