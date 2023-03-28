from IPInfo import getIP, getIPRisk, checkRBL
from MastodonFunctions import sendWelcomeMessage
from disposable_email_domains import blocklist


def formatMastodonHook(data):
    event = data['event']
    if event.startswith('account.'):
        account = data['object']
        username = account['username']
        display_name = account['account']['display_name'] or username
        if event == 'account.created':
            email = f"`{account['email']}`"
            if not account['confirmed']:
                email += " *(not confirmed)*"
            if email.partition('@')[2] in blocklist:
                email += (
                        "  \n**Disposable Email:** "
                        "This looks like it might be a disposable email address  \n"
                        )
            ip = account['ip']
            account_id = account['id']
            country = getIP(ip)
            rblRisk = checkRBL(ip)
            ipRisk = getIPRisk(ip)
            risk = []
            ipRep = ""
            if rblRisk:
                risk.append(rblRisk)
            if ipRisk:
                risk.append(ipRisk)
            if rblRisk or ipRisk:
                riskTxt = ", ".join(risk)
                ipRep = f"**IP Reputation:** {riskTxt}  \n"
            reason = account['invite_request']
            return (
                f"## New account created  \n"
                f"**Display Name:** `{display_name}`  \n"
                f"**User:** `{username}`  \n"
                f"**Email:** {email}  \n"
                f"**IP:** `{ip}` *({country})* [More info at IPinfo.io](https://ipinfo.io/{ip})  \n"
                f"{ipRep}"
                f"**Reason:**  \n"
                f"> {reason}  \n\n"
                f"https://raphus.social/admin/accounts/{account_id}"
                )
        if event == 'account.approved':
            sendWelcomeMessage(username)
            return (
                f"## New account approved  \n"
                f"**Display Name:** `{display_name}`  \n"
                f"**User:** `{username}`  \n"
                f"*Welcome message has been sent*"
                )
    else:
        import json
        return "```\n"+json.dumps(data, indent=2)+"\n```"
