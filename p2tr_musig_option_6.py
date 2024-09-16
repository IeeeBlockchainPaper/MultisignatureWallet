# Imports
from io import BytesIO
import random
import util
from test_framework.key import generate_key_pair, generate_bip340_key_pair_from_xprv, generate_bip340_key_pair, generate_schnorr_nonce, EllipticCurve, ECKey, ECPubKey, SECP256K1_FIELD_SIZE, SECP256K1, SECP256K1_ORDER
from test_framework.musig import aggregate_musig_signatures, aggregate_schnorr_nonces, generate_musig_key, musig_digest, sign_musig
from test_framework.script import *
from test_framework.address import program_to_witness
from test_framework.messages import CTransaction, COutPoint, CTxIn, CTxOut, CTxInWitness
from test_framework.util import assert_equal
from itertools import combinations
from copy import deepcopy

OP_dict = {
    1: OP_1,
    2: OP_2,
    3: OP_3,
    4: OP_4,
    5: OP_5,
    6: OP_6,
    7: OP_7,
    8: OP_8,
    9: OP_9,
    10: OP_10,
    11: OP_11,
    12: OP_12,
    13: OP_13,
    14: OP_14,
    15: OP_15,
    16: OP_16
}
# Step 1: No. of cosigners
def p2tr_musig_option_6(logger=False):
    
    
    try:
        n = int(input("Please enter N: "))
        m = int(input("Please enter M: "))
        if m > 16 or n > 16 or m <= 0 or n <= 0 or m > n:
            raise Exception("Invalid M and N")
    except Exception as e:
        raise Exception("Invalid M and N")

    try:
        privkeys = list()
        pubkeys = list()
        # xprivkey = "tprv8ZgxMBicQKsPdCi1rfrmrrccbRK2KQTedehgv3zN4MtdLuUkJkBG1xBrqmAJ4bnv4DAPuS2Bc4rxn5qCJXDemy1SSVUBKqUxHLJXorxxLoR"
        
        
        for i in range(n):
            _xprivkey = input(f"Enter extended private key for cosigner {i+1}:")
            _path = input(f"Enter the derivation path for cosigner {i+1}. If you are not sure what this is, leave this field unchanged.")
            if(len(_path) == 0):
                _path = "m//86'/1'/0'/0/{}".format(i+1)
            _privkey, _pubkey = generate_bip340_key_pair_from_xprv(_xprivkey,_path)
            privkeys.append(_privkey)
            pubkeys.append(_pubkey)

        print(f"\nFollowing are the generated {n} public and private keys.", end='\n\n')
        for idx, pk, privk in zip([i + 1 for i in range(n)], pubkeys, privkeys):
            print(f"Public Key {idx}: {pk}")
            # print(f"Private Key {idx}: {privk}")
            print(f"Size of Public Key {idx} is: {len(pk.get_bytes())} bytes", end='\n\n')

        
        c_map, musig_agg = generate_musig_key(pubkeys)
        logger.warning(f"MuSig pubkey: {musig_agg.get_bytes().hex()}")
        print(f"Size of Aggregated Public Key is: {len(musig_agg.get_bytes())} bytes", end='\n\n')

    except Exception as e:
        raise(e)
    finally:
        test.shutdown()
