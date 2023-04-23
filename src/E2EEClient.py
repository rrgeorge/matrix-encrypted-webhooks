import aiohttp
import json
import logging
import os
import sys
import re
from typing import Optional
from MastodonFunctions import sendWelcomeMessage, checkEmail
import IPInfo
from markdown import markdown
from nio import (
    AsyncClient,
    AsyncClientConfig,
    LoginResponse,
    MatrixRoom,
    RoomMessageText,
    UnknownEvent,
    SyncResponse,
    KeyVerificationCancel,
    KeyVerificationEvent,
    KeyVerificationKey,
    KeyVerificationMac,
    KeyVerificationStart,
    ToDeviceEvent,
    ToDeviceError,
    Event
)
from termcolor import colored


class E2EEClient:
    def __init__(self, join_rooms: set):
        self.STORE_PATH = os.environ['LOGIN_STORE_PATH']
        self.CONFIG_FILE = f"{self.STORE_PATH}/credentials.json"

        self.join_rooms = join_rooms
        self.client: AsyncClient = None
        self.client_config = AsyncClientConfig(
            max_limit_exceeded=0,
            max_timeouts=0,
            store_sync_tokens=True,
            encryption_enabled=True,
        )

        self.greeting_sent = False

    def _write_details_to_disk(self, resp: LoginResponse, homeserver) -> None:
        with open(self.CONFIG_FILE, "w") as f:
            json.dump(
                {
                    'homeserver': homeserver,  # e.g. "https://matrix.example.org"
                    'user_id': resp.user_id,  # e.g. "@user:example.org"
                    'device_id': resp.device_id,  # device ID, 10 uppercase letters
                    'access_token': resp.access_token  # cryptogr. access token
                },
                f
            )

    async def _login_first_time(self) -> None:
        homeserver = os.environ['MATRIX_SERVER']
        user_id = os.environ['MATRIX_USERID']
        pw = os.environ['MATRIX_PASSWORD']
        device_name = os.environ['MATRIX_DEVICE']

        if not os.path.exists(self.STORE_PATH):
            os.makedirs(self.STORE_PATH)

        self.client = AsyncClient(
            homeserver,
            user_id,
            store_path=self.STORE_PATH,
            config=self.client_config,
            ssl=(os.environ['MATRIX_SSLVERIFY'] == 'True'),
        )

        resp = await self.client.login(password=pw, device_name=device_name)

        if (isinstance(resp, LoginResponse)):
            self._write_details_to_disk(resp, homeserver)
        else:
            logging.info(
                f"homeserver = \"{homeserver}\"; user = \"{user_id}\"")
            logging.critical(f"Failed to log in: {resp}")
            sys.exit(1)

    async def _login_with_stored_config(self) -> None:
        if self.client:
            return

        with open(self.CONFIG_FILE, "r") as f:
            config = json.load(f)

            self.client = AsyncClient(
                config['homeserver'],
                config['user_id'],
                device_id=config['device_id'],
                store_path=self.STORE_PATH,
                config=self.client_config,
                ssl=bool(os.environ['MATRIX_SSLVERIFY']),
            )

            self.client.restore_login(
                user_id=config['user_id'],
                device_id=config['device_id'],
                access_token=config['access_token']
            )

    async def login(self) -> None:
        if os.path.exists(self.CONFIG_FILE):
            logging.info('Logging in using stored credentials.')
        else:
            logging.info('First time use, did not find credential file.')
            await self._login_first_time()
            logging.info(
                f"Logged in, credentials are stored under '{self.STORE_PATH}'.")

        await self._login_with_stored_config()

    async def _message_callback(self, room: MatrixRoom, event: RoomMessageText) -> None:
        logging.info(colored(
            f"@{room.user_name(event.sender)} in {room.display_name} | {event.body}",
            'green'
        ))
        if event.body.startswith("!"):
            await self.client.room_typing(room.room_id, True)
        if event.body == "!users":
            await self.get_users(room.room_id)
        if event.body.startswith("!checkemail "):
            await self.get_checkemail(room.room_id, event.body[12:].strip())
        if event.body.startswith("!checkip "):
            await self.get_checkip(room.room_id, event.body[9:].strip())
        if event.body == "!testwelcome":
            sendWelcome = sendWelcomeMessage("raphus")
            await self.send_message(sendWelcome, room.room_id, 'command')
        if event.body == "!help":
            await self.send_message((
                "I understand the following commands:  \n"
                "> `!users`  \n"
                ">> Get current user stats  \n\n"
                "> `!checkip <ip address>`  \n"
                ">> Get info about given ip address  \n"
                ">> Can also be invoked by reacting 💻 to a New User message  \n\n"
                "> `!checkemail <username>`  \n"
                ">> Check if given user has confirmed their email address yet  \n"
                ">> Can also be invoked by reacting 📧 to a New User message"
                ), room.room_id, 'command')
        if event.body.startswith("!"):
            await self.client.room_typing(room.room_id, False)
        await self.client.update_receipt_marker(room.room_id, event.event_id)

    async def _emote_callback(self, room: MatrixRoom, event: UnknownEvent) -> None:
        try:
            if event.type != 'm.reaction':
                return
            reaction = event.source['content']['m.relates_to']
            src_event = await self.client.room_get_event(room.room_id, reaction['event_id'])
            message = src_event.event.body
            await self.client.room_typing(room.room_id, True)
            if message.startswith('## New account signup'):
                if reaction['key'] in ['📧', '✉️', '📩']:
                    username = re.search(r'\*\*User:\*\* `(.*?)`', message).group(1)
                    if checkEmail(username):
                        new_message = message.replace('*(not confirmed)*', '*(confirmed)*')
                        await self.send_message(
                            new_message,
                            room.room_id,
                            'reaction',
                            False,
                            reaction['event_id']
                        )
                    # await self.get_checkemail(room.room_id, username)
                elif reaction['key'] in ['💻', '💻️']:
                    ip = re.search(r'\*\*IP:\*\* `(.*?)`', message).group(1)
                    await self.get_checkip(room.room_id, ip)
                else:
                    logging.info(f"Not sure what to do with {reaction['key']}")
            elif reaction['key'] == '📝':
                logging.info(f"Received memo, sending edit\n{message}")
                logging.info(str(src_event.event))
                await self.send_message(
                        message + "  \n\nEdited.",
                        room.room_id,
                        'reaction',
                        False,
                        reaction['event_id']
                )
            else:
                logging.info(f"Not sure what to do with {reaction['key']}")
            await self.client.room_typing(room.room_id, False)
        except Exception as e:
            err = str(e)
            logging.error(f"Error: {err}")

    async def _sync_callback(self, response: SyncResponse) -> None:
        logging.debug(f"We synced, token: {response.next_batch}")

        if not self.greeting_sent:
            self.greeting_sent = True

            greeting = (
                    f"Hi, I'm up and runnig from **{os.environ['MATRIX_DEVICE']}**, "
                    f"waiting for webhooks!"
                    )
            await self.send_message(greeting, os.environ['MATRIX_ADMIN_ROOM'], 'Webhook server')


    async def _device_callback(self, event):  # noqa
        print(event)
        """Handle events sent to device."""
        try:
            client = self.client

            if isinstance(event, KeyVerificationStart):  # first step
                """first step: receive KeyVerificationStart
                KeyVerificationStart(
                    source={'content':
                            {'method': 'm.sas.v1',
                             'from_device': 'DEVICEIDXY',
                             'key_agreement_protocols':
                                ['curve25519-hkdf-sha256', 'curve25519'],
                             'hashes': ['sha256'],
                             'message_authentication_codes':
                                ['hkdf-hmac-sha256', 'hmac-sha256'],
                             'short_authentication_string':
                                ['decimal', 'emoji'],
                             'transaction_id': 'SomeTxId'
                             },
                            'type': 'm.key.verification.start',
                            'sender': '@user2:example.org'
                            },
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    from_device='DEVICEIDXY',
                    method='m.sas.v1',
                    key_agreement_protocols=[
                        'curve25519-hkdf-sha256', 'curve25519'],
                    hashes=['sha256'],
                    message_authentication_codes=[
                        'hkdf-hmac-sha256', 'hmac-sha256'],
                    short_authentication_string=['decimal', 'emoji'])
                """

                if "emoji" not in event.short_authentication_string:
                    print(
                        "Other device does not support emoji verification "
                        f"{event.short_authentication_string}."
                    )
                    return
                resp = await client.accept_key_verification(event.transaction_id)
                if isinstance(resp, ToDeviceError):
                    print(f"accept_key_verification failed with {resp}")

                sas = client.key_verifications[event.transaction_id]

                todevice_msg = sas.share_key()
                resp = await client.to_device(todevice_msg)
                if isinstance(resp, ToDeviceError):
                    print(f"to_device failed with {resp}")

            elif isinstance(event, KeyVerificationCancel):  # anytime
                """at any time: receive KeyVerificationCancel
                KeyVerificationCancel(source={
                    'content': {'code': 'm.mismatched_sas',
                                'reason': 'Mismatched authentication string',
                                'transaction_id': 'SomeTxId'},
                    'type': 'm.key.verification.cancel',
                    'sender': '@user2:example.org'},
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    code='m.mismatched_sas',
                    reason='Mismatched short authentication string')
                """

                # There is no need to issue a
                # client.cancel_key_verification(tx_id, reject=False)
                # here. The SAS flow is already cancelled.
                # We only need to inform the user.
                print(
                    f"Verification has been cancelled by {event.sender} "
                    f'for reason "{event.reason}".'
                )

            elif isinstance(event, KeyVerificationKey):  # second step
                """Second step is to receive KeyVerificationKey
                KeyVerificationKey(
                    source={'content': {
                            'key': 'SomeCryptoKey',
                            'transaction_id': 'SomeTxId'},
                        'type': 'm.key.verification.key',
                        'sender': '@user2:example.org'
                    },
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    key='SomeCryptoKey')
                """
                sas = client.key_verifications[event.transaction_id]

                print(f"{sas.get_emoji()}")

                yn = input("Do the emojis match? (Y/N) (C for Cancel) ")
                if yn.lower() == "y":
                    print(
                        "Match! The verification for this " "device will be accepted."
                    )
                    resp = await client.confirm_short_auth_string(event.transaction_id)
                    if isinstance(resp, ToDeviceError):
                        print(f"confirm_short_auth_string failed with {resp}")
                elif yn.lower() == "n":  # no, don't match, reject
                    print(
                        "No match! Device will NOT be verified "
                        "by rejecting verification."
                    )
                    resp = await client.cancel_key_verification(
                        event.transaction_id, reject=True
                    )
                    if isinstance(resp, ToDeviceError):
                        print(f"cancel_key_verification failed with {resp}")
                else:  # C or anything for cancel
                    print("Cancelled by user! Verification will be " "cancelled.")
                    resp = await client.cancel_key_verification(
                        event.transaction_id, reject=False
                    )
                    if isinstance(resp, ToDeviceError):
                        print(f"cancel_key_verification failed with {resp}")

            elif isinstance(event, KeyVerificationMac):  # third step
                """Third step is to receive KeyVerificationMac
                KeyVerificationMac(
                    source={'content': {
                        'mac': {'ed25519:DEVICEIDXY': 'SomeKey1',
                                'ed25519:SomeKey2': 'SomeKey3'},
                        'keys': 'SomeCryptoKey4',
                        'transaction_id': 'SomeTxId'},
                        'type': 'm.key.verification.mac',
                        'sender': '@user2:example.org'},
                    sender='@user2:example.org',
                    transaction_id='SomeTxId',
                    mac={'ed25519:DEVICEIDXY': 'SomeKey1',
                         'ed25519:SomeKey2': 'SomeKey3'},
                    keys='SomeCryptoKey4')
                """
                sas = client.key_verifications[event.transaction_id]
                try:
                    todevice_msg = sas.get_mac()
                except LocalProtocolError as e:
                    # e.g. it might have been cancelled by ourselves
                    print(
                        f"Cancelled or protocol error: Reason: {e}.\n"
                        f"Verification with {event.sender} not concluded. "
                        "Try again?"
                    )
                else:
                    resp = await client.to_device(todevice_msg)
                    if isinstance(resp, ToDeviceError):
                        print(f"to_device failed with {resp}")
                    print(
                        f"sas.we_started_it = {sas.we_started_it}\n"
                        f"sas.sas_accepted = {sas.sas_accepted}\n"
                        f"sas.canceled = {sas.canceled}\n"
                        f"sas.timed_out = {sas.timed_out}\n"
                        f"sas.verified = {sas.verified}\n"
                        f"sas.verified_devices = {sas.verified_devices}\n"
                    )
                    print(
                        "Emoji verification was successful!\n"
                        "Hit Control-C to stop the program or "
                        "initiate another Emoji verification from "
                        "another device or room."
                    )
            else:
                print(
                    f"Received unexpected event type {type(event)}. "
                    f"Event is {event}. Event will be ignored."
                )
        except BaseException:
            print(traceback.format_exc())

    async def send_message(
        self,
        message: str,
        room: str,
        sender: str,
        sync: Optional[bool] = False,
        replacing: Optional[str] = None
    ) -> None:
        if sync:
            await self.client.sync(timeout=3000, full_state=True)

        msg_prefix = ""
        if os.environ['DISPLAY_APP_NAME'] == 'True':
            msg_prefix = f"**{sender}** says:  \n"

        content = {
            'msgtype': 'm.text',
            'body': f"{msg_prefix}{message}",
        }
        if replacing:
            content['m.relates_to'] = {
                'rel_type': 'm.replace',
                'event_id': replacing
            }
            content['m.new_content'] = {
                'msgtype': 'm.text',
                'body': f"{msg_prefix}{message}",
            }
        if os.environ['USE_MARKDOWN'] == 'True':
            # Markdown formatting removes YAML newlines if not padded with spaces,
            # and can also mess up posted data like system logs
            logging.debug('Markdown formatting is turned on.')

            content['format'] = 'org.matrix.custom.html'
            content['formatted_body'] = markdown(
                f"{msg_prefix}{message}", extensions=['extra'])
            if replacing:
                content['m.new_content']['format'] = 'org.matrix.custom.html'
                content['m.new_content']['formatted_body'] = markdown(
                    f"{msg_prefix}{message}", extensions=['extra'])

        await self.client.room_send(
            room_id=room,
            message_type="m.room.message",
            content=content,
            ignore_unverified_devices=True
        )

    async def get_users(self, room) -> None:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{os.environ['MASTODON_INSTANCE']}/nodeinfo/2.0") as response:
                if response.status == 200:
                    json = await response.json()
                    stats = (
                            f"## Current User Stats: 📊  \n"
                            f"👥 **Active users:** {json['usage']['users']['activeMonth']},  \n"
                            f"📈 **Total users**: {json['usage']['users']['total']},  \n"
                            f"📨 **Total Posts:** {json['usage']['localPosts']}"
                            )
                    await self.send_message(stats, room, 'command')

    async def get_checkemail(self, room, user) -> None:
        emailstatus = checkEmail(user)
        if isinstance(emailstatus, bool):
            if not emailstatus:
                await self.send_message(f"User '{user}' has not confirmed their email yet.",
                                        room,
                                        'command')
            else:
                await self.send_message(f"User '{user}' has confirmed their email.",
                                        room,
                                        'command')
        else:
            await self.send_message(f"Could not check user '{user}': {emailstatus}",
                                    room,
                                    'command')

    async def get_checkip(self, room, ip) -> None:
        ipRisk = IPInfo.getIPRisk(ip)
        rblRisk = IPInfo.checkRBL(ip)
        ipInfo = IPInfo.getIP(ip)
        ipRep = await IPInfo.checkIPRep(ip)
        isRisk = "No known risk"
        isp = ""
        risk = []
        if rblRisk:
            risk.append(rblRisk)
        if ipRisk:
            risk.append(ipRisk)
        if ipRep['success']:
            isp = f"**ISP:** {ipRep['ISP']}  \n"
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
            isRisk = f"**IP Reputation:** {riskTxt}"
        await self.send_message((
            f"**IP:** `{ip}` *({ipInfo})*  \n"
            f"{isp}"
            f"{isRisk}"
            ),
            room,
            'command')

    async def run(self) -> None:
        try:
            await self.login()

            self.client.add_event_callback(self._message_callback, RoomMessageText)
            self.client.add_event_callback(self._emote_callback, UnknownEvent)
            self.client.add_response_callback(self._sync_callback, SyncResponse)
            self.client.add_to_device_callback(self._device_callback, (ToDeviceEvent,))
            if self.client.should_upload_keys:
                await self.client.keys_upload()
            for room in self.join_rooms:
                await self.client.join(room)
            await self.client.joined_rooms()
            logging.info('The Matrix client is waiting for events.')

            await self.client.sync_forever(timeout=300000, full_state=True)
        except Exception as e:
            print(e)
