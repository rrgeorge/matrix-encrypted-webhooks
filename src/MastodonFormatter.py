from IPInfo import getIP, getIPRisk, checkRBL, checkIPRep
from MastodonFunctions import sendWelcomeMessage
from disposable_email_domains import blocklist


async def formatMastodonHook(data):
    event = data['event']
    if event.startswith('account.'):
        account = data['object']
        username = account['username']
        display_name = account['account']['display_name'] or username
        if event == 'account.created':
            email = f"`{account['email']}`"
            if not account['confirmed']:
                email += " *(not confirmed)*"
            if f"`{account['email']}`".partition('@')[2] in blocklist:
                email += (
                        "  \n🕳️ **Disposable Email:** "
                        "This looks like it might be a disposable email address  \n"
                        )
            ip = account['ip']
            account_id = account['id']
            country = getIP(ip)
            rblRisk = checkRBL(ip)
            ipRisk = getIPRisk(ip)
            ipRep = await checkIPRep(ip)
            risk = []
            isRisk = ""
            isp = ""
            if rblRisk:
                risk.append(rblRisk)
            if ipRisk:
                risk.append(ipRisk)
            if ipRep['success']:
                isp = f"📡 **ISP:** {ipRep['ISP']}  \n"
                if ipRep['fraud_score'] > 75:
                    risk.append('Address may be suspicious')
                if ipRep['tor']:
                    risk.append('TOR Address')
                if ipRep['vpn']:
                    risk.append('VPN Address')
                if ipRep['proxy']:
                    risk.append('Proxy Address')
                if ipRep['bot_status']:
                    risk.append('Known bot ip')
            if len(risk) > 0:
                riskTxt = ", ".join(risk)
                isRisk = isp + f"⚠️ **IP Reputation:** {riskTxt}  \n"
            reason = account['invite_request']
#           Log reasons
            with open('seen_reasons.txt', 'a+') as f:
                f.write(f"{reason}\n")
            return (
                f"## New account signup 📋  \n"
                f"👤 **Display Name:** `{display_name}`  \n"
                f"🔖 **User:** `{username}`  \n"
                f"📧 **Email:** {email}  \n"
                f"🌐**IP:** `{ip}` *({country})*  \n"
                f"{isRisk}"
                f"📝 **Signup Reason:**  \n"
                f"> {reason}  \n\n"
                f"https://raphus.social/admin/accounts/{account_id}"
                )
        if event == 'account.approved':
            sendWelcomeMessage(username)
            return (
                f"## New account approved 🎉  \n"
                f"👤 **Display Name:** `{display_name}`  \n"
                f"🔖 **User:** `{username}`  \n"
                f"*Welcome message has been sent* 👋"
                )
    if event.startswith('report.created'):
        report_id = data['object']['id']
        reported = data['object']['target_account']['account']['acct']
        source = data['object']['account']['account']['acct']
        category = data['object']['category']
        comment = data['object']['comment']
        statuses = len(data['object']['statuses'])
        pl = 's' if statuses > 1 else ''
        icon = '🐷' if category == "spam" else '👮' if category == 'violation' else '⛔'
        return (
            f"## New report opened 🚨  \n"
            f"{icon} {reported} has been reported by {source} for "
            f"{category} on {statuses} post{pl}  \n"
            f"> {comment}  \n\n"
            f"https://raphus.social/admin/reports/{report_id}"
                )
    else:
        import json
        return "```\n"+json.dumps(data, indent=2)+"\n```  \n"
