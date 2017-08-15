import binascii
import logging
logger = logging.getLogger(__name__)
import sys
import json
import time
import requests

from itertools import groupby

from counterpartylib.lib import config
from counterpartycli.util import wallet_api as rpc

def get_wallet_addresses():
    addresses = []
    for group in rpc('listaddressgroupings', []):
        for bunch in group:
            address, btc_balance = bunch[:2]
            addresses.append(address)
    return addresses

def get_btc_balances_old():
    for group in rpc('listaddressgroupings', []):
        for bunch in group:
            yield bunch[:2]

def get_btc_balances():
    balances = [(unspent['address'], unspent['amount']) for unspent in rpc('listunspent')]
    for addr, group in groupby(sorted(balances, key=lambda x: x[0]), key=lambda x: x[0]):
        yield [addr, sum(map(lambda x: x[1], group))]

def list_unspent():
    return rpc('listunspent', [0, 99999])

def sign_raw_transaction(tx_hex):
    return rpc('signrawtransaction', [tx_hex])['hex']

def is_valid(address):
    return rpc('validateaddress', [address])['isvalid']

def is_mine(address):
    logging.warning(address)
    res = rpc('validateaddress', [address])
    logging.warning(res)
    return res['ismine']

def get_pubkey(address):
    address_infos = rpc('validateaddress', [address])
    if address_infos['isvalid'] and address_infos['ismine']:
        return address_infos['pubkey']
    return None

def get_btc_balance_old(address):
    for group in rpc('listaddressgroupings', []):
        for bunch in group:
            btc_address, btc_balance = bunch[:2]
            if btc_address == address:
                return btc_balance
    return 0

def get_btc_balance(address):
    return sum([unspent['amount'] for unspent in rpc('listunspent') if unspent['address'] == address])
    #total = 0
    #for unspent in rpc('listunspent', []):
    #    if unspent['address'] == address:
    #        total = total + unspent[amount
    #return total

def is_locked():
    getinfo = rpc('getinfo', [])
    if 'unlocked_until' in getinfo:
        if getinfo['unlocked_until'] >= 10:
            return False # Wallet is unlocked for at least the next 10 seconds.
        else:
            return True # Wallet is locked
    else:
        False

def unlock(passphrase):
    return rpc('walletpassphrase', [passphrase, 60])

def send_raw_transaction(tx_hex):
    return rpc('sendrawtransaction', [tx_hex])

def wallet_last_block():
    getinfo = rpc('getinfo', [])
    return getinfo['blocks']

# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
