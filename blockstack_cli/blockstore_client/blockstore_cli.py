#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
    Blockstore-client
    ~~~~~
    copyright: (c) 2014-2015 by Halfmoon Labs, Inc.
    copyright: (c) 2016 by Blockstack.org

    This file is part of Blockstore-client.

    Blockstore-client is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Blockstore-client is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.
    You should have received a copy of the GNU General Public License
    along with Blockstore-client.  If not, see <http://www.gnu.org/licenses/>.
"""

import argparse
import sys
import json
import traceback
import os
import pybitcoin
from socket import error as socket_error

import requests
requests.packages.urllib3.disable_warnings()

import logging
logging.disable(logging.CRITICAL)

# Hack around absolute paths
current_dir = os.path.abspath(os.path.dirname(__file__))
parent_dir = os.path.abspath(current_dir + "/../")

sys.path.insert(0, parent_dir)

from blockstore_client import config, client, schemas, parsing, user
from blockstore_client import storage, drivers
from blockstore_client.utils import pretty_dump, print_result
from blockstore_client.config import WALLET_PATH, WALLET_PASSWORD_LENGTH

from blockstore_client.parser import add_subparsers, add_advanced_subparsers
from blockstore_client.parser import AliasedSubParsersAction

from registrar.wallet import HDWallet
from registrar.crypto.utils import aes_encrypt, aes_decrypt
from registrar.blockchain import get_balance
from registrar.network import get_bs_client
from registrar.rpc_daemon import background_process
from registrar.utils import satoshis_to_btc
from registrar.states import nameRegistered, ownerName, profileonBlockchain
from registrar.blockchain import recipientNotReady, get_tx_confirmations

from binascii import hexlify

import xmlrpclib

from registrar.config import REGISTRAR_IP, REGISTRAR_PORT

RPC_DAEMON = 'http://' + REGISTRAR_IP + ':' + str(REGISTRAR_PORT)

log = config.log


def initialize_wallet():

    result = {}
    print "Initializing new wallet ..."
    password = "temp"

    try:
        while len(password) < WALLET_PASSWORD_LENGTH:
            password = raw_input("Enter new password: ")

            if len(password) < WALLET_PASSWORD_LENGTH:
                msg = "Password is too short. Please make it at"
                msg += " least %s characters long" % WALLET_PASSWORD_LENGTH
                print msg
            else:

                wallet = HDWallet()
                hex_password = hexlify(password)
                hex_privkey = wallet.get_master_privkey()

                data = {}
                encrypted_key = aes_encrypt(hex_privkey, hex_password)
                data['encrypted_master_private_key'] = encrypted_key

                file = open(WALLET_PATH, 'w')
                file.write(json.dumps(data))
                file.close()

                print "Wallet created. Make sure to backup the following:"

                result['wallet_password'] = password
                result['master_private_key'] = hex_privkey

    except KeyboardInterrupt:
        print "\nExited."

    return result


def unlock_wallet(display_enabled=False):

    if walletUnlocked():
        if display_enabled:
            payment_address, owner_address = get_addresses_from_memory()
            display_wallet_info(payment_address, owner_address)
    else:

        try:
            password = raw_input("Enter wallet password: ")
            hex_password = hexlify(password)

            file = open(WALLET_PATH, 'r')
            data = file.read()
            data = json.loads(data)
            hex_privkey = None
            try:
                hex_privkey = aes_decrypt(data['encrypted_master_private_key'],
                                          hex_password)
            except:
                print "Incorrect password."
            else:
                print "Unlocked wallet."
                wallet = HDWallet(hex_privkey)
                child = wallet.get_child_keypairs(count=2,
                                                  include_privkey=True)
                payment_keypair = child[0]
                owner_keypair = child[1]
                save_keys_to_memory(payment_keypair, owner_keypair)

                if display_enabled:
                    display_wallet_info(payment_keypair[0], owner_keypair[0])
        except KeyboardInterrupt:
            print "\nExited."


def walletUnlocked():

    payment_address, owner_address = get_addresses_from_memory()

    if payment_address is not None and owner_address is not None:

        return True
    else:
        return False


def display_wallet_info(payment_address, owner_address):

    print '-' * 60
    print "Payment address:\t%s" % payment_address
    print "Owner address:\t\t%s" % owner_address
    print '-' * 60
    print "Balance:"
    print "%s: %s" % (payment_address, get_balance(payment_address))
    print '-' * 60

    print "Names Owned:"
    names_owned = get_names_owned(owner_address)
    print "%s: %s" % (owner_address, names_owned)
    print '-' * 60


def get_names_owned(address):

    bs_client = get_bs_client()

    try:
        names_owned = bs_client.get_names_owned_by_address(address)
    except socket_error:
        names_owned = "Error connecting to server"

    return names_owned


def get_local_proxy():

    proxy = xmlrpclib.ServerProxy(RPC_DAEMON)

    try:
        data = proxy.ping()
    except:
        log.debug('RPC daemon is not online')
        return False

    return proxy


def start_background_daemons():

    proxy = xmlrpclib.ServerProxy(RPC_DAEMON)

    try:
        data = proxy.ping()
    except:
        pass
        background_process('start_daemon')
        background_process('start_monitor')


def save_keys_to_memory(payment_keypair, owner_keypair):

    proxy = get_local_proxy()

    if proxy is False:
        exit_with_error('Error talking to local proxy')

    data = proxy.set_wallet(payment_keypair, owner_keypair)


def get_addresses_from_memory():

    proxy = get_local_proxy()

    if proxy is False:
        return None, None

    data = json.loads(proxy.get_wallet())

    return data['payment_address'], data['owner_address']


def get_payment_addresses():

    payment_addresses = []

    # currently only using one
    payment_address, owner_address = get_addresses_from_memory()

    payment_addresses.append({'address': payment_address,
                              'balance': get_balance(payment_address)})

    return payment_addresses


def get_owner_addresses():

    owner_addresses = []

    # currently only using one
    payment_address, owner_address = get_addresses_from_memory()

    owner_addresses.append({'address': owner_address,
                            'names': get_names_owned(owner_address)})

    return owner_addresses


def get_all_names_owned():

    owner_addresses = get_owner_addresses()

    names_owned = []

    for entry in owner_addresses:

        additional_names = get_names_owned(entry['address'])
        for name in additional_names:
            names_owned.append(name)

    return names_owned


def get_total_balance():

    payment_addresses = get_payment_addresses()

    total_balance = 0.0

    for entry in payment_addresses:

        total_balance += float(entry['balance'])

    return total_balance, payment_addresses


def approx_tx_fees(num_tx):
    """ Just a rough approximation on tx fees
        It slightly over estimates
        Should be replaced by checking for fee estimation from bitcoind
    """
    APPROX_FEE_PER_TX = 8000  # in satoshis
    return num_tx * APPROX_FEE_PER_TX


def hasEnoughBalance(payment_address, cost):

    total_balance = get_balance(payment_address)

    if total_balance > cost:
        return True
    else:
        return False


def get_total_fees(data):

    reply = {}

    registration_fee_satoshi = data['satoshis']
    tx_fee_satoshi = approx_tx_fees(num_tx=2)

    registration_fee = satoshis_to_btc(registration_fee_satoshi)
    tx_fee = satoshis_to_btc(tx_fee_satoshi)

    details = {}
    details['registration_fee'] = registration_fee
    details['transactions_fee'] = tx_fee
    reply['total_cost'] = registration_fee + tx_fee
    reply['details'] = details

    return reply


def exit_with_error(error_message, help_message=None):

    result = {'error': error_message}

    if help_message is not None:
        result['help'] = help_message
    print_result(result)
    exit(0)


def tests_for_update_and_transfer(fqu, transfer_address=None):
    """ Any update or transfer operation
        should pass these tests
    """

    if not nameRegistered(fqu):
        exit_with_error("%s is not registered yet" % fqu)

    if not walletUnlocked():
        exit_with_error("Unlock wallet first.")

    payment_address, owner_address = get_addresses_from_memory()

    if not ownerName(fqu, owner_address):
        exit_with_error("%s not owned by %s" % (fqu, owner_address))

    tx_fee_satoshi = approx_tx_fees(num_tx=1)
    tx_fee = satoshis_to_btc(tx_fee_satoshi)

    if not hasEnoughBalance(payment_address, tx_fee):
        msg = "Address %s doesn't have enough balance" % payment_address
        exit_with_error(msg)

    if transfer_address is not None:
        if recipientNotReady(transfer_address):
            msg = "Address %s owns too many names already." % transfer_address
            exit_with_error(msg)


def get_sorted_commands(display_commands=False):
    """ when adding new commands to the parser, use this function to
        check the correct sorted order
    """

    command_list = ['status', 'ping', 'preorder', 'register', 'update',
                    'transfer', 'renew', 'name_import', 'namespace_preorder',
                    'namespace_ready', 'namespace_reveal', 'put_mutable',
                    'put_immutable', 'get_mutable', 'get_immutable',
                    'cost', 'get_namespace_cost', 'get_nameops_at',
                    'get_name_blockchain_record', 'get_namespace_blockchain_record',
                    'get_name_record', 'lookup',
                    'get_all_names', 'get_names_in_namespace', 'consensus',
                    'lookup_snv', 'get_names_owned_by_address',
                    'preorder_tx', 'preorder_subsidized',
                    'register_tx', 'register_subsidized',
                    'update_tx', 'update_subsidized',
                    'transfer_tx', 'transfer_subsidized',
                    'revoke_tx', 'revoke_subsidized',
                    'renew_tx', 'renew_subsidized']

    if display_commands:
        for cmd in sorted(command_list):
            log.debug(cmd)

    return command_list


def run_cli():
    """ run cli
    """

    conf = config.get_config()

    if conf is None:
        log.error("Failed to load config")
        sys.exit(1)

    advanced_mode = conf['advanced_mode']

    parser = argparse.ArgumentParser(
      description='Blockstack cli version {}'.format(config.VERSION))

    parser.register('action', 'parsers', AliasedSubParsersAction)

    subparsers = parser.add_subparsers(
      dest='action')

    add_subparsers(subparsers)

    if advanced_mode == "on":
        add_advanced_subparsers(subparsers)

    # Print default help message, if no argument is given
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args, unknown_args = parser.parse_known_args()
    result = {}

    conf = config.get_config()

    blockstore_server = conf['server']
    blockstore_port = conf['port']

    proxy = client.session(conf=conf, server_host=blockstore_server,
                           server_port=blockstore_port, set_global=True)

    # start the two background processes (rpc daemon and monitor queue)
    start_background_daemons()

    if args.action == 'balance':

        if not walletUnlocked():
            unlock_wallet()

        result['total_balance'], result['addresses'] = get_total_balance()

    elif args.action == 'config':
        data = {}

        settings_updated = False

        data["message"] = "Updated settings for"

        if args.host is not None:
            config.update_config('blockstack-client', 'server', args.host)
            data["message"] += " host"
            settings_updated = True

        if args.port is not None:
            config.update_config('blockstack-client', 'port', args.port)
            data["message"] += " port"
            settings_updated = True

        if args.advanced is not None:

            if args.advanced != "on" and args.advanced != "off":
                exit_with_error("Use --advanced=on or --advanced=off")
            else:
                config.update_config('blockstack-client', 'advanced_mode', args.advanced)
                data["message"] += " advanced"
                settings_updated = True

        # reload conf
        conf = config.get_config()

        result['host'] = conf['server']
        result['port'] = conf['port']
        result['advanced'] = conf['advanced_mode']

        if settings_updated:
            result['message'] = data['message']

    elif args.action == 'deposit':

        if not walletUnlocked():
            unlock_wallet()

        result['message'] = 'Send bitcoins to the address specified.'
        result['address'], owner_address = get_addresses_from_memory()

    elif args.action == 'import':

        if not walletUnlocked():
            unlock_wallet()

        result['message'] = 'Send the name you want to receive to the'
        result['message'] += ' address specified.'
        payment_address, result['address'] = get_addresses_from_memory()

    elif args.action == 'names':

        if not walletUnlocked():
            unlock_wallet()

        result['names_owned'] = get_all_names_owned()
        result['addresses'] = get_owner_addresses()

    elif args.action in ('info', 'status', 'ping', 'details'):

        resp = client.getinfo()

        result = {}

        result['server_host'] = conf['server']
        result['server_port'] = str(conf['port'])
        result['cli_version'] = config.VERSION
        result['advanced_mode'] = conf['advanced_mode']

        if 'error' in resp:
            result['server_alive'] = False
            result['server_error'] = resp['error']
        else:
            result['server_alive'] = True
            result['server_version'] = resp['blockstore_version']
            try:
                result['last_block_processed'] = resp['last_block']
            except:
                result['last_block_processed'] = resp['blocks']
            result['last_block_seen'] = resp['bitcoind_blocks']
            result['consensus_hash'] = resp['consensus']

            if advanced_mode == 'on':
                result['testset'] = resp['testset']

            proxy = get_local_proxy()

            if proxy is not False:

                current_state = json.loads(proxy.state())

                pending_queue = []
                preorder_queue = []
                register_queue = []
                update_queue = []
                transfer_queue = []

                def format_new_entry(entry):
                    new_entry = {}
                    new_entry['name'] = entry['fqu']
                    confirmations = get_tx_confirmations(entry['tx_hash'])
                    if confirmations is None:
                        confirmations = 0
                    new_entry['confirmations'] = confirmations
                    return new_entry

                def format_queue_display(pending_queue, preorder_queue,
                                         register_queue):

                    for entry in preorder_queue:

                        name = entry['name']

                        for check_entry in pending_queue:

                            if check_entry['name'] == name:
                                pending_queue.remove(check_entry)

                    for entry in register_queue:

                        name = entry['name']

                        for check_entry in preorder_queue:

                            if check_entry['name'] == name:
                                preorder_queue.remove(check_entry)

                for entry in current_state:

                    if 'type' in entry:
                        if entry['type'] == 'pending':
                            pending_queue.append(format_new_entry(entry))
                        elif entry['type'] == 'preorder':
                            preorder_queue.append(format_new_entry(entry))
                        elif entry['type'] == 'register':
                            register_queue.append(format_new_entry(entry))
                        elif entry['type'] == 'update':
                            update_queue.append(format_new_entry(entry))
                        elif entry['type'] == 'transfer':
                            transfer_queue.append(format_new_entry(entry))

                format_queue_display(pending_queue, preorder_queue,
                                     register_queue)

                if len(pending_queue) != 0:
                    result['queue_pending'] = pending_queue

                if len(preorder_queue) != 0:
                    result['queue_preorder'] = preorder_queue

                if len(register_queue) != 0:
                    result['queue_register'] = register_queue

                if len(update_queue) != 0:
                    result['queue_update'] = update_queue

                if len(transfer_queue) != 0:
                    result['queue_transfer'] = transfer_queue

    elif args.action == 'wallet':

        if not os.path.exists(WALLET_PATH):
            result = initialize_wallet()
        else:
            unlock_wallet(display_enabled=True)

    elif args.action == 'lookup':
        data = {}

        blockchain_record = None

        try:
            blockchain_record = client.get_name_blockchain_record(
                                        str(args.name))
        except socket_error:
            exit_with_error("Error connecting to server")

        try:
            data_id = blockchain_record['value_hash']
            data['data_record'] = json.loads(
                client.get_immutable(str(args.name), data_id)['data'])
        except:
            data['data_record'] = None

        result = data

    elif args.action == 'whois':
        data = {}

        record = None

        try:
            record = client.get_name_blockchain_record(
                                        str(args.name))
        except socket_error:
            exit_with_error("Error connecting to server")

        if 'value_hash' not in record:
            result['registered'] = False
        else:
            result['registered'] = True
            result['block_preordered_at'] = record['preorder_block_number']
            result['block_renewed_at'] = record['last_renewed']
            result['owner_address'] = record['address']
            result['owner_public_key'] = record['sender_pubkey']
            result['owner_script'] = record['sender']
            result['preorder_transaction_id'] = record['txid']

    elif args.action == 'register':
        result = {}
        fqu = str(args.name)
        cost = client.get_name_cost(fqu)

        if 'error' in cost:
            msg = "This namespace doesn't exist, try using namespaces like .id"
            exit_with_error(msg)

        if nameRegistered(fqu):
            exit_with_error("%s is already registered" % fqu)

        if not walletUnlocked():
            exit_with_error("Unlock wallet first.")

        fees = get_total_fees(cost)

        try:
            cost = fees['total_cost']
            input_prompt = "Registering %s will cost %s BTC." % (fqu, cost)
            input_prompt += " Continue? (y/n): "
            user_input = raw_input(input_prompt)
            user_input = user_input.lower()

            if user_input != 'y':
                print "Not registering."
                exit(0)
        except KeyboardInterrupt:
            print "\nExiting."
            exit(0)

        proxy = get_local_proxy()
        result = proxy.register(fqu)

    elif args.action == 'update':

        fqu = str(args.name)

        user_data = str(args.data)
        try:
            user_data = json.loads(user_data)
        except:
            exit_with_error("data is not in JSON format")

        if profileonBlockchain(fqu, user_data):
            msg = "data is same as current data record, update not needed"
            exit_with_error(msg)

        tests_for_update_and_transfer(fqu)

        proxy = get_local_proxy()
        result = proxy.update(fqu, user_data)

    elif args.action == 'transfer':

        fqu = str(args.name)
        transfer_address = str(args.address)

        tests_for_update_and_transfer(fqu, transfer_address=transfer_address)

        proxy = get_local_proxy()
        result = proxy.transfer(fqu, transfer_address)

    elif args.action == 'consensus':

        if args.block_height is None:
            # by default get last indexed block
            resp = client.getinfo()

            if 'error' in resp:
                exit_with_error("Error connecting to server")

            elif 'last_block' in resp or 'blocks' in resp:

                if 'last_block' in resp:
                    args.block_height = client.getinfo()['last_block']
                elif 'blocks' in resp:
                    args.block_height = client.getinfo()['blocks']
                else:
                    result['error'] = "Server is indexing. Try again"
                    exit(0)

        resp = client.get_consensus_at(int(args.block_height))

        data = {}
        data['consensus'] = resp
        data['block_height'] = args.block_height

        result = data

    # ---------------------- Advanced options ---------------------------------
    elif args.action == 'register_tx':
        result = client.register(str(args.name), str(args.privatekey),
                                 str(args.addr), tx_only=True)

    elif args.action == 'register_subsidized':
        result = client.register_subsidized(str(args.name), str(args.privatekey),
                                            str(args.addr), str(args.subsidy_key))

    elif args.action == 'update_tx':

        txid = None
        if args.txid is not None:
            txid = str(args.txid)

        result = client.update(str(args.name),
                               str(args.record_json),
                               str(args.privatekey),
                               txid=txid, tx_only=True)

    elif args.action == 'update_subsidized':

        txid = None
        if args.txid is not None:
            txid = str(args.txid)

        result = client.update_subsidized(str(args.name),
                                          str(args.record_json),
                                          str(args.public_key),
                                          str(args.subsidy_key),
                                          txid=txid)

    elif args.action == 'transfer_tx':
        keepdata = False
        if args.keepdata.lower() not in ["on", "false"]:
            print >> sys.stderr, "Pass 'true' or 'false' for keepdata"
            sys.exit(1)

        if args.keepdata.lower() == "on":
            keepdata = True

        result = client.transfer(str(args.name),
                                 str(args.address),
                                 keepdata,
                                 str(args.privatekey),
                                 tx_only=True)

    elif args.action == 'preorder':

        register_addr = None
        if args.address is not None:
            register_addr = str(args.address)

        result = client.preorder(str(args.name), str(args.privatekey),
                                 register_addr=register_addr)

    elif args.action == 'preorder_tx':

        register_addr = None
        if args.address is not None:
            register_addr = str(args.address)

        result = client.preorder(str(args.name), str(args.privatekey),
                                 register_addr=register_addr, tx_only=True)

    elif args.action == 'preorder_subsidized':

        result = client.preorder_subsidized(str(args.name),
                                            str(args.public_key),
                                            str(args.address),
                                            str(args.subsidy_key))

    elif args.action == 'transfer_subsidized':
        keepdata = False
        if args.keepdata.lower() not in ["on", "false"]:
            print >> sys.stderr, "Pass 'true' or 'false' for keepdata"
            sys.exit(1)

        if args.keepdata.lower() == "on":
            keepdata = True

        result = client.transfer_subsidized(str(args.name),
                                            str(args.address),
                                            keepdata,
                                            str(args.public_key),
                                            str(args.subsidy_key))

    elif args.action == 'renew':
        result = client.renew(str(args.name), str(args.privatekey))

    elif args.action == 'renew_tx':
        result = client.renew(str(args.name), str(args.privatekey),
                              tx_only=True)

    elif args.action == 'renew_subsidized':
        result = client.renew_subsidized(str(args.name), str(args.public_key),
                                         str(args.subsidy_key))

    elif args.action == 'revoke':
        result = client.revoke(str(args.name), str(args.privatekey))

    elif args.action == 'revoke_tx':
        result = client.revoke(str(args.name), str(args.privatekey),
                               tx_only=True)

    elif args.action == 'revoke_subsidized':
        result = client.revoke_subsidized(str(args.name), str(args.public_key),
                                          str(args.subsidy_key))

    elif args.action == 'name_import':
        result = client.name_import(str(args.name), str(args.address),
                                    str(args.hash), str(args.privatekey))

    elif args.action == 'namespace_preorder':

        reveal_addr = None
        if args.address is not None:
            reveal_addr = str(args.address)

        result = client.namespace_preorder(str(args.namespace_id),
                                           str(args.privatekey),
                                           reveal_addr=reveal_addr)

    elif args.action == 'namespace_reveal':
        bucket_exponents = args.bucket_exponents.split(',')
        if len(bucket_exponents) != 16:
            raise Exception("bucket_exponents must be a 16-value CSV \
                             of integers")

        for i in xrange(0, len(bucket_exponents)):
            try:
                bucket_exponents[i] = int(bucket_exponents[i])
            except:
                raise Exception("bucket_exponents must contain integers in \
                                range [0, 16)")

        lifetime = int(args.lifetime)
        if lifetime < 0:
            lifetime = 0xffffffff       # means "infinite" to blockstack-server

        result = client.namespace_reveal(str(args.namespace_id),
                                         str(args.addr),
                                         lifetime,
                                         int(args.coeff),
                                         int(args.base),
                                         bucket_exponents,
                                         int(args.nonalpha_discount),
                                         int(args.no_vowel_discount),
                                         str(args.privatekey))

    elif args.action == 'namespace_ready':
        result = client.namespace_ready(str(args.namespace_id),
                                        str(args.privatekey))

    elif args.action == 'put_mutable':
        result = client.put_mutable(str(args.name),
                                    str(args.data_id),
                                    str(args.data),
                                    str(args.privatekey))

    elif args.action == 'put_immutable':
        result = client.put_immutable(str(args.name),
                                      str(args.data),
                                      str(args.privatekey),
                                      conf=conf)

    elif args.action == 'get_mutable':
        result = client.get_mutable(str(args.name), str(args.data_id),
                                    conf=conf)

    elif args.action == 'get_immutable':
        result = client.get_immutable(str(args.name), str(args.hash))

    elif args.action == 'delete_immutable':
        result = client.delete_immutable(str(args.name), str(args.hash),
                                         str(args.privatekey))

    elif args.action == 'delete_mutable':
        result = client.delete_mutable(str(args.name), str(args.data_id),
                                       str(args.privatekey))

    elif args.action == 'get_name_blockchain_record':
        result = client.get_name_blockchain_record(str(args.name))

    elif args.action == 'get_namespace_blockchain_record':
        result = client.get_namespace_blockchain_record(str(args.namespace_id))

    elif args.action == 'lookup_snv':
        result = client.lookup_snv(str(args.name), int(args.block_id),
                                   str(args.consensus_hash))

    elif args.action == 'get_name_record':
        result = client.get_name_record(str(args.name))

    elif args.action == 'cost':

        fqu = str(args.name)

        try:
            resp = client.get_name_cost(fqu)
        except socket_error:
            exit_with_error("Error connecting to server")

        if 'satoshis' not in resp:
            exit_with_error("%s is not a valid name" % fqu)

        data = get_total_fees(resp)

        result = data

    elif args.action == 'get_names_owned_by_address':
        result = client.get_names_owned_by_address(str(args.address))

    elif args.action == 'get_namespace_cost':
        result = client.get_namespace_cost(str(args.namespace_id))

    elif args.action == 'get_all_names':
        offset = None
        count = None

        if args.offset is not None:
            offset = int(args.offset)

        if args.count is not None:
            count = int(args.count)

        result = client.get_all_names(offset, count)

    elif args.action == 'get_names_in_namespace':
        offset = None
        count = None

        if args.offset is not None:
            offset = int(args.offset)

        if args.count is not None:
            count = int(args.count)

        result = client.get_names_in_namespace(str(args.namespace_id), offset,
                                               count)

    elif args.action == 'get_nameops_at':
        result = client.get_nameops_at(int(args.block_id))

    print_result(result)

if __name__ == '__main__':
    try:
        run_cli()
    except:
        exit_with_error("Unexpected error. Try getting latest version of CLI" +
                        "'sudo pip install blockstack --upgrade'")
