import os
from mastodon import Mastodon


mastodon = Mastodon(
        access_token=os.environ['MASTODON_TOKEN'],
        api_base_url=os.environ['MASTODON_INSTANCE']
        )


def sendWelcomeMessage(account_id):
    message = f"@{account_id} " + os.environ['MASTODON_WELCOME']
    mastodon.status_post(message, visibility='direct')
    return f"Sent welcome message to {account_id}."


def isConfirmed(account_id):
    return mastodon.admin_account(account_id).confirmed


def checkEmail(user):
    print("checking email for user", user)
    try:
        res = mastodon.admin_accounts_v2(origin="local", username=user)
        for a in res:
            if a.username.lower() == user.lower():
                return isConfirmed(a.id)
        return "Invalid username"
    except Exception as e:
        print(e)
        return "Error"
