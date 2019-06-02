#!/usr/bin/env python
# coding: utf-8
##############################################################################
# Copyright © 2019 Henrik Lindgren
# This work is free. You can redistribute it and/or modify it under the
# terms of the Do What The Fuck You Want To Public License, Version 2,
# as published by Sam Hocevar. See http://www.wtfpl.net/ for more details.
##############################################################################
# This is a command line tool to perform remote commands on your
# Minecraft Realm.
#
# Following links provided inspiration and documentation.
# https://wiki.vg/Authentication
# https://wiki.vg/Realms_API
# https://wiki.vg/Mojang_API

import os
from functools import lru_cache
import requests
import json
import logging
import uuid
import argparse


AUTH_SERVER = 'https://authserver.mojang.com'
REALMS_ENDPOINT = 'https://pc.realms.minecraft.net'
UUID_ENDPOINT = 'https://api.mojang.com/users/profiles/minecraft'
MINECRAFT_VERSION = os.environ.get('MINECRAFT_VERSION', '1.14.2')
# 8MB, a map is easily 300 MB and we can easily store 8MB in ram for the purpose.
CHUNK_BUFFER_SIZE = 1024 * 1024 * 8


class Session(object):
    """
    see https://wiki.vg/Authentication
    """
    def __init__(self, username, email, password, client_secret=None):
        self.client_secret = uuid.uuid4().hex if client_secret is None else client_secret
        self.email = email
        self.username = username
        self.password = password
        self.agent = {'name': 'Minecraft', 'version': 1}
        self.auth_uri = AUTH_SERVER
        self.token = None
        self.logged_in = False

    @staticmethod
    @lru_cache(maxsize=32)
    def get_username_uuid(username):
        """
        See https://wiki.vg/Mojang_API#Username_-.3E_UUID_at_time
        :param username:
        :return: uuid for username
        """
        r = requests.get(f'{UUID_ENDPOINT}/{username}')
        if r.status_code != 200:
            raise ValueError('HTTP status code not 200')
        try:
            json_response = json.loads(r.text)
        except json.JSONDecodeError:
            logging.exception('Failed to parse JSON from response.')
            raise
        return json_response['id']

    def get_url(self, url):
        """
        Used to call URL's requiring active session.

        :param url:
        :return:
        """
        username_uuid = self.get_username_uuid(self.username)
        cookies = {
            'sid': f'token:{self.token}:{username_uuid}',
            'user': self.username,
            'version': MINECRAFT_VERSION
        }
        return requests.get(url, cookies=cookies)

    def update_token_from_auth_response(self, auth_response):
        try:
            response_json = json.loads(auth_response)
        except json.JSONDecodeError:
            logging.exception(
                'Couldn\'t parse auth response into '
                'json, response was %s', auth_response)
            raise
        try:
            self.token = response_json['accessToken']
        except KeyError as e:
            logging.exception(
                'Couldn\'t find auth token when parsing auth '
                'response. Response was %s', response_json)
            raise
        return self.token

    def login(self):
        data = {
            'agent': self.agent,
            'username': self.email,
            'password': self.password,
            'clientToken': self.client_secret
        }
        r = requests.post(f'{self.auth_uri}/authenticate', json=data)
        if r.status_code == 200:
            logging.info('Successfully logged in to account %s', self.email)
            self.logged_in = True
            return self.update_token_from_auth_response(r.text)
        raise RuntimeError(
            'Could not authenticate with auth server. '
            f'status_code={r.status_code} response={r.text}')

    def logout(self):
        data = {
            'username': self.email,
            'password': self.password,
        }
        r = requests.post(f'{self.auth_uri}/signout', json=data)
        if r.status_code != 204:
            raise ValueError(f'Couldn\'t sign out from session, status_code={r.status_code}, text={r.text}')
        logging.info('Successfully logged out from account %s', self.email)
        self.logged_in = False

    def __enter__(self):
        self.login()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.logout()
        return self


class Client(object):
    def __init__(self, username, email, password, client_secret=None):
        self.session = Session(username, email, password, client_secret=client_secret)
        self._worlds = None

    def get_worlds(self):
        if self._worlds is None:
            r = self.session.get_url(f'{REALMS_ENDPOINT}/worlds')
            self._worlds = json.loads(r.text)
        return self._worlds

    def get_world(self, index: int = 1):
        try:
            return self.get_worlds()['servers'][index - 1]
        except IndexError:
            return None

    def get_latest_backup(self, index: int = 1, backup_folder='backups'):
        world = self.get_world(index)
        world_id = world['id']
        r = self.session.get_url(f'{REALMS_ENDPOINT}/worlds/{world_id}/slot/{index}/download')
        if r.status_code != 200:
            raise ValueError(f'Could not get latest backup http status code:{r.status_code} reason:{r.text}')
        download_url = json.loads(r.text)['downloadLink']
        logging.info('About to fetch latest backup for world with index %s, from url %s', index, download_url)
        # get the filename between the last slash and the ? at the end for the filename
        backup_filename = download_url.rsplit('/')[-1].split('?')[0]
        save_path = os.path.join(backup_folder, backup_filename)
        with requests.get(download_url, stream=True) as r:
            r.raise_for_status()
            transferred = 0
            with open(save_path, 'wb') as backup_file:
                logging.info('Saving backup to %s', save_path)
                for chunk in r.iter_content(chunk_size=CHUNK_BUFFER_SIZE):
                    if chunk:
                        backup_file.write(chunk)
                        transferred += CHUNK_BUFFER_SIZE
                        print(f'... {transferred/1024/1024} MB')
                backup_file.flush()
            logging.info('Save complete.')

    @staticmethod
    def get_players(world: dict):
        return world['players']

    def __enter__(self):
        self.session.__enter__()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.session.__exit__(exc_type, exc_val, exc_tb)
        return self


if __name__ == "__main__":
    def world_index_range(value):
        return isinstance(value, int) and 1 <= value <= 4

    try:
        logging.getLogger().setLevel(logging.INFO)
        parser = argparse.ArgumentParser(description='Automation tool for Minecraft Realms.')
        parser.add_argument('--username', default=os.environ.get('MINECRAFT_USERNAME'))
        parser.add_argument('--email', default=os.environ.get('MINECRAFT_USER_EMAIL'))
        parser.add_argument('--password', default=os.environ.get('MINECRAFT_PASSWORD'))
        parser.add_argument('--latest-backup', action='store_true', help='Download latest backup.')
        parser.add_argument('--save-path', default=os.getcwd(), help='Where to save latest backup.')
        parser.add_argument('--world-index', type=world_index_range, default=1,
                            help='Index of world 1-4, defaults to 1')
        parser.add_argument('--worlds', action='store_true', help='Print worlds\' information.')
        args = parser.parse_args()
        if not args.username or not args.email or not args.password:
            # Missing obligatory values for any command.
            exit(parser.print_help())
        elif not any([args.latest_backup, args.worlds]):
            # Missing any actionable command, no need to start up session.
            exit(parser.print_help())

        with Client(username=args.username, email=args.email, password=args.password) as client:
            if args.worlds:
                # show world information
                print(client.get_worlds())
            if args.latest_backup:
                # download latest backup using default or supplied options
                client.get_latest_backup(index=args.world_index, backup_folder=args.save_path)

    except Exception:
        logging.exception('Unhandled error occured, see trace.')
        raise
