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
        await self.client.update_receipt_marker(room.room_id, event.event_id)

    async def _emote_callback(self, room: MatrixRoom, event: UnknownEvent) -> None:
        try:
            if event.type != 'm.reaction':
                return
            reaction = event.source['content']['m.relates_to']
            src_event = await self.client.room_get_event(room.room_id, reaction['event_id'])
            message = src_event.event.body
            if message.startswith('## New account created'):
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
                elif reaction['key'] == '💻':
                    ip = re.search(r'\*\*IP:\*\* `(.*?)`', message).group(1)
                    await self.get_checkip(room.room_id, ip)
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
        except Exception as e:
            err = str(e)
            logging.error(f"Error: {err}")

    async def _sync_callback(self, response: SyncResponse) -> None:
        logging.info(f"We synced, token: {response.next_batch}")

        if not self.greeting_sent:
            self.greeting_sent = True

            greeting = (
                    f"Hi, I'm up and runnig from **{os.environ['MATRIX_DEVICE']}**, "
                    f"waiting for webhooks!"
                    )
            await self.send_message(greeting, os.environ['MATRIX_ADMIN_ROOM'], 'Webhook server')

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
                            f"## Current User Stats:  \n"
                            f"**Active users:** {json['usage']['users']['activeMonth']},  \n"
                            f"**Total users**: {json['usage']['users']['total']},  \n"
                            f"**Total Posts:** {json['usage']['localPosts']}"
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
        ipRep = "No known risk"
        risk = []
        if rblRisk:
            risk.append(rblRisk)
        if ipRisk:
            risk.append(ipRisk)
        if rblRisk or ipRisk:
            riskTxt = ", ".join(risk)
            ipRep = f"**IP Reputation:** {riskTxt}"
        await self.send_message((
            f"**IP:** `{ip}` *({ipInfo})* [More info at IPinfo.io](https://ipinfo.io/{ip})  \n"
            f"{ipRep}"
            ),
            room,
            'command')

    async def run(self) -> None:
        await self.login()

        self.client.add_event_callback(self._message_callback, RoomMessageText)
        self.client.add_event_callback(self._emote_callback, UnknownEvent)
        self.client.add_response_callback(self._sync_callback, SyncResponse)
        if self.client.should_upload_keys:
            await self.client.keys_upload()

        logging.info('The Matrix client is waiting for events.')

        await self.client.sync_forever(timeout=300000, full_state=True)
