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

def p2tr_musig_option_5(logger=False):
    
    try:
        n = int(input("Please enter N: "))
        m = int(input("Please enter M: "))
        if m > 16 or n > 16 or m <= 0 or n <= 0 or m > n:
            raise Exception("Invalid M and N")
    except Exception as e:
        raise Exception("Invalid M and N")
    print("\n\n #######  \'P2TR only script path Multisig\' Output Transaction Details  #######   \n\n")
    try:
        privkeys = list()
        pubkeys = list()

        for i in range(n):
            # _xprivkey = input(f"Enter extended private key for cosigner {i+1}:")
            # _path = input(f"Enter the derivation path for cosigner {i+1}. If you are not sure what this is, leave this field unchanged.")
            # if(len(_path) == 0):
            #     _path = "m//86'/1'/0'/0/{}".format(i+1)
            # _privkey, _pubkey = generate_bip340_key_pair_from_xprv(_xprivkey,_path)
            # privkeys.append(_privkey)
            # pubkeys.append(_pubkey)
            _privkey, _pubkey = generate_bip340_key_pair()
            privkeys.append(_privkey)
            pubkeys.append(_pubkey)

        print(f"\nFollowing are the {n} public keys.", end='\n\n')
        for idx, pk, privk in zip([i + 1 for i in range(n)], pubkeys, privkeys):
            print(f"Public Key {idx}: {pk}")
            # print(f"Private Key {idx}: {privk}")
            print(f"Size of Public Key {idx} is: {len(pk.get_bytes())} bytes", end='\n\n')

        
        c_map, musig_agg = generate_musig_key(pubkeys)
        logger.warning(f"MuSig aggregated pubkey: {musig_agg.get_bytes().hex()}")
        print(f"Size of Aggregated Public Key is: {len(musig_agg.get_bytes())} bytes", end='\n\n')
        # generate NUMS key
        SECP256K1_FIELD_SIZE = 2**256 - 2**32 - 977
        SECP256K1 = EllipticCurve(SECP256K1_FIELD_SIZE, 0, 7)
        SECP256K1_G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798, 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8, 1)
                    
        x,y,z = SECP256K1.lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
        H = ECPubKey()
        # H.p = SECP256K1.lift_x(0x50929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0)
        # print(H.valid)
        H.set(x.to_bytes(32,'big'))
        r = random.randrange(1, SECP256K1_ORDER)#.to_bytes(32, 'big')
        # H + rG
        ret = ECPubKey()
        p = SECP256K1.mul([(SECP256K1_G, r)])
        ret.p = p
        ret.valid = True
        ret.compressed = True
        final = ECPubKey()
        final = ret + H
        print(f"NUMS point for key path: {final}")
        combs = list(combinations(pubkeys, m))
        print("Following are the Script path Tapscripts: \n")
        tapscripts = list()
        for comb in combs:
            # print(comb)
            tapscripts.append(TapLeaf().construct_csa(m, comb))

        for tapscript in tapscripts:
            for op in tapscript.script:
                print(op.hex()) if isinstance(op, bytes) else print(op)
            print()

        tapscript_weights = [(1, tapscript) for tapscript in tapscripts]
        multisig_taproot = TapTree(key = musig_agg)
        multisig_taproot.huffman_constructor(tapscript_weights)

        # print(f"Taproot descriptor: {multisig_taproot.desc}\n")
        # print(f"taproot script: {multisig_taproot.root.script}")
        # for op in multisig_taproot.root.script:
        #     if isinstance(op, bytes):
        #         print(op.hex())
        #     else:
        #         print(op)
        # # print("\nSatisfying witness elements:")
        # for element, value in multisig_taproot.root.sat:
        #     print("{}, {}".format(element, value.hex()))
            
        # Derive segwit v1 address
        tapscript, taptweak, control_map = multisig_taproot.construct()
        taptweak = int.from_bytes(taptweak, 'big')
        output_pubkey = final.tweak_add(taptweak)
        output_pubkey_b = output_pubkey.get_bytes()
        segwit_address = program_to_witness(1, output_pubkey_b)
        print(f"Taproot Output Public Key: {output_pubkey}")
        print(f"Taproot Locking Script: ")
        for op in tapscript:
            if isinstance(op, bytes):
                print(op.hex())
            else:
                print(op)
        print(f"Taproot Locking Script Size: {len(tapscript)}")
        logger.warning(f"Taproot Address: {segwit_address}")
        # print(f"Taproot locking script size: {len(segwit_address)}")
        logger.warning(f"Taproot address size: {len(bytearray(segwit_address.encode()))} bytes")
        # Setup test node
        test = util.TestWrapper()
        test.setup()
        test.nodes[0].generate(101)

        # Send funds to taproot output.
        txid = test.nodes[0].sendtoaddress(address=segwit_address, amount=0.5, fee_rate=25)
        # Deserialize wallet transaction.
        tx = CTransaction()
        tx_hex = test.nodes[0].getrawtransaction(txid)
        tx.deserialize(BytesIO(bytes.fromhex(tx_hex)))
        tx.rehash()
        # The wallet randomizes the change output index for privacy
        # Loop through the outputs and return the first where the scriptPubKey matches the segwit v1 output
        output_index, output = next(out for out in enumerate(tx.vout) if out[1].scriptPubKey == tapscript)
        output_value = output.nValue
        tx_information = test.nodes[0].decoderawtransaction(tx.serialize().hex())
        print(f"Transaction size: {tx_information['size']}")
        print(f"Transaction vsize: {tx_information['vsize']}")
        print(f"Transaction Weight: {tx_information['weight']}")
        
        print("\n\n #######  \'P2TR only script path Multisig\' Spending Transaction Details  #######   \n\n")
        # Create Spending Tx
        spending_tx = CTransaction()
        spending_tx.nVersion = 1
        spending_tx.nLockTime = 0
        outpoint = COutPoint(tx.sha256, output_index)
        spending_tx_in = CTxIn(outpoint = outpoint)
        spending_tx.vin = [spending_tx_in]

        # Generate new Bitcoin Core wallet address
        dest_addr = test.nodes[0].getnewaddress(address_type="bech32")
        scriptpubkey = bytes.fromhex(test.nodes[0].getaddressinfo(dest_addr)['scriptPubKey'])

        # Determine minimum fee required for mempool acceptance
        min_fee = int(test.nodes[0].getmempoolinfo()['mempoolminfee'] * 100000000)

        # Complete output which returns funds to Bitcoin Core wallet
        dest_output = CTxOut(nValue=output_value - min_fee, scriptPubKey=scriptpubkey)
        spending_tx.vout = [dest_output]

        # Construct transaction
        spending_tx = CTransaction()

        #spending_tx.nVersion = 2
        spending_tx.nLockTime = 0
        outpoint = COutPoint(tx.sha256, output_index)
        spending_tx_in = CTxIn(outpoint=outpoint)
        spending_tx.vin = [spending_tx_in]
        spending_tx.vout = [dest_output]

        # Add signatures to the witness
        sigs = [CScript() for i in range(n)]

        print("Please specify the order in which you would like to apply the M private keys.")
        print("Application will prompt for M times. Each time, pass the key number out of [1, 2, ... M] and press Enter.", end='\n\n')
        priority_order = list()
        correct = True
        for i in range(m):
            order = int(input(f"Please enter private Key number {i + 1}: "))
            if order > n or (order - 1) in priority_order or order <= 0:
                correct = False
                continue
            priority_order.append(order - 1)

        if len(priority_order) != m or not correct:
            raise Exception("Incorrect or duplicate key added")
        priority_order.sort()
        tapscript_ = TapLeaf().construct_csa(m, [pubkeys[i] for i in priority_order])
        sighash = TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT, 0, scriptpath=True, script=tapscript_.script)
        print(f"Script path witness_elements: ")
        witness_elements = []
        # Add signatures to the witness
        sigs = []
        for i in priority_order:
            sigs.append(privkeys[i].sign_schnorr(sighash))
            
        # Add witness to transaction
        reversed_sigs = list(reversed(sigs))

        for sig in reversed_sigs:
            print(f"{sig}\n")
            witness_elements.append(sig)
            
        witness_elements.append(tapscript_.script)
        for op in tapscript_.script:
            print(op.hex()) if isinstance(op, bytes) else print(op)
        print()
        witness_elements.append(control_map[tapscript_.script])
        # print("witness_elements: ", witness_elements)
        print(f"{control_map[tapscript_.script].hex()}\n")
        spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))
        spending_tx_str = spending_tx.serialize().hex()

        # print("testmempoolaccept: ", test.nodes[0].testmempoolaccept([spending_tx_str]))
        # print("test_transaction: ",test.nodes[0].test_transaction(spending_tx))
        
        tx_information = test.nodes[0].decoderawtransaction(spending_tx.serialize().hex())
        # print(f"Transaction Id: {tx_information['txid']}")
        logger.warning(f"Transaction Id: {tx_information['txid']}")
        print(f"Transaction size: {tx_information['size']}")
        print(f"Transaction vsize: {tx_information['vsize']}")
        print(f"Transaction Weight: {tx_information['weight']}")
        print(f"Transaction sent to: {dest_addr}")

    except Exception as e:
        raise(e)
    finally:
        test.shutdown()
