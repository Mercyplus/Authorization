import os
import hashlib
import binascii

from bip32utils import BIP32Key
from eth_keys import keys


def generate_memo(m):
    memo_str = os.urandom(8)
    m.update(memo_str)
    memo_str = binascii.hexlify(memo_str + m.digest()[0:2])
    return memo_str


def init_profile(user, is_social=False, metamask_address=None, lang='en', swaps=False):
    m = hashlib.sha256()
    memo_str1 = generate_memo(m)
    # memo_str2 = generate_memo(m)
    # memo_str3 = generate_memo(m)
    memo_str4 = generate_memo(m)
    memo_str5 = generate_memo(m)
    # memo_str6 = generate_memo(m)

    wish_key = BIP32Key.fromExtendedKey(ROOT_PUBLIC_KEY, public=True)
    # eosish_key = BIP32Key.fromExtendedKey(ROOT_PUBLIC_KEY_EOSISH, public=True)
    # tron_key = BIP32Key.fromExtendedKey(ROOT_PUBLIC_KEY_TRON, public=True)
    swaps_key = BIP32Key.fromExtendedKey(ROOT_PUBLIC_KEY_SWAPS, public=True)
    protector_key = BIP32Key.fromExtendedKey(ROOT_PUBLIC_KEY_PROTECTOR, public=True)

    btc_address1 = wish_key.ChildKey(user.id).Address()
    # btc_address2 = eosish_key.ChildKey(user.id).Address()
    # btc_address3 = tron_key.ChildKey(user.id).Address()
    btc_address4 = swaps_key.ChildKey(user.id).Address()
    btc_address5 = protector_key.ChildKey(user.id).Address()
    # btc_address6 = swaps_key.ChildKey(user.id).Address()
    eth_address1 = keys.PublicKey(wish_key.ChildKey(user.id).K.to_string()).to_checksum_address().lower()
    # eth_address2 = keys.PublicKey(eosish_key.ChildKey(user.id).K.to_string()).to_checksum_address().lower()
    # eth_address3 = keys.PublicKey(tron_key.ChildKey(user.id).K.to_string()).to_checksum_address().lower()
    eth_address4 = keys.PublicKey(swaps_key.ChildKey(user.id).K.to_string()).to_checksum_address().lower()
    eth_address5 = keys.PublicKey(protector_key.ChildKey(user.id).K.to_string()).to_checksum_address().lower()
    # eth_address6 = keys.PublicKey(swaps_key.ChildKey(user.id).K.to_string()).to_checksum_address().lower()
