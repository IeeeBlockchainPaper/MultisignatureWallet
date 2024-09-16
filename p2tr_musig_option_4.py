# Imports
from io import BytesIO
import random
import util
from test_framework.key import generate_key_pair, generate_bip340_key_pair_from_xprv, generate_bip340_key_pair, generate_schnorr_nonce, ECKey, ECPubKey, SECP256K1_FIELD_SIZE, SECP256K1, SECP256K1_ORDER
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

def p2tr_musig_option_4(logger=False):
    
    try:
        n = int(input("Please enter N: "))
        m = int(input("Please enter M: "))
        if m > 16 or n > 16 or m <= 0 or n <= 0 or m > n:
            raise Exception("Invalid M and N")
    except Exception as e:
        raise Exception("Invalid M and N")
    print("\n\n #######  \'P2TR multiple m-of-m musig TapScript Multisig\' Output Transaction Details  #######   \n\n")
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
        keys = list(zip(pubkeys, privkeys))
        print(f"\nFollowing are the {n} public keys.", end='\n\n')
        for idx, pk, privk in zip([i + 1 for i in range(n)], pubkeys, privkeys):
            print(f"Public Key {idx}: {pk}")
            # print(f"Private Key {idx}: {privk}")
            print(f"Size of Public Key {idx} is: {len(pk.get_bytes())} bytes", end='\n\n')

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
        pubkeys_c = [pubkeys[i] for i in priority_order]
        privkeys_c = list()

        c_map, musig_agg = generate_musig_key(pubkeys_c)

        for i in range(m):
            idx = priority_order[i]
            privkeys_c.append(privkeys[idx].mul(c_map[pubkeys[idx]]))
            
        if musig_agg.get_y()%2 != 0:
            musig_agg.negate()
            for i in range(m):
                privkeys_c[i].negate()

        logger.warning(f"MuSig aggregated pubkey: {musig_agg.get_bytes().hex()}")
        print(f"Size of Aggregated Public Key is: {len(musig_agg.get_bytes())} bytes", end='\n\n')
        
        combs = list(combinations(keys, m))
        updated_combs = list()
        tapscripts = list()
        print("Following are the Script path Tapscripts: \n")
        for comb in combs:
            comb_pub = [i for (i, j) in comb]
            comb_priv = [j for (i, j) in comb]
            # Skip the combination matching with the order provided by User
            if comb_pub == pubkeys_c:
                continue
                
            c_map, musig_agg_ = generate_musig_key(comb_pub)
            for i in range(m):
                comb_priv[i] = comb_priv[i].mul(c_map[comb_pub[i]])

            if musig_agg_.get_y()%2 != 0:
                musig_agg_.negate()
                for i in range(m):
                    comb_priv[i].negate()

            tapleaf = TapLeaf().construct_pk(musig_agg_)
            tapscripts.append(tapleaf)
            comb = [comb_pub, comb_priv, musig_agg_, tapleaf]
            updated_combs.append(comb)

        tapscript_weights = [(1, tapscript) for tapscript in tapscripts]

        for tapscript in tapscripts:
            for op in tapscript.script:
                print(op.hex()) if isinstance(op, bytes) else print(op)
            print()

        # Construct taptree with huffman constructor
        multisig_taproot = TapTree(key = musig_agg)
        multisig_taproot.huffman_constructor(tapscript_weights)

        # Derive segwit v1 address
        tapscript, taptweak, control_map = multisig_taproot.construct()
        taptweak = int.from_bytes(taptweak, 'big')
        output_pubkey = musig_agg.tweak_add(taptweak)
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

        print("\n\n #######  \'P2TR multiple m-of-m musig TapScripts Multisig\' Spending Transaction Details  #######   \n\n")
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

        choice = util.propmt_musig_options()
        if choice == 1:
            # Key path spending
            # Negate keys if necessary
            output_keyPath = output_pubkey
            tweak_keyPath = taptweak
            if output_keyPath.get_y()%2 != 0:
                output_keyPath.negate()
                for i in range(n):
                    privkeys_c[i].negate()
                tweak_keyPath = SECP256K1_ORDER - taptweak

            # Create sighash for ALL
            sighash_musig = TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT)
            
            # Generate individual nonces for participants and an aggregate nonce point
            noncelist = list()
            noncepointlist = list()
            for i in range(m):
                noncelist.append(generate_schnorr_nonce())
                noncepointlist.append(noncelist[i].get_pubkey())

            R_agg, negated = aggregate_schnorr_nonces(noncepointlist)
            if negated:
                for i in range(m):
                    noncelist[i].negate()

            # Create an aggregate signature.
            sigs = list()
            for i in range(m):
                sigs.append(sign_musig(privkeys_c[i], noncelist[i], R_agg, output_pubkey, sighash_musig))
                
            e = musig_digest(R_agg, output_keyPath, sighash_musig)
            sigs.append(e * tweak_keyPath)
            sig_agg = aggregate_musig_signatures(sigs, R_agg)
            # print("sig_agg: ",len(sig_agg))

            
            print(f"Aggregate signature is {sig_agg.hex()}\n")

            assert output_keyPath.verify_schnorr(sig_agg, sighash_musig)

            # Construct transaction witness
            spending_tx.wit.vtxinwit.append(CTxInWitness([sig_agg]))
            
            # print(f"spending_tx: {spending_tx}\n")

            # Test mempool acceptance
            spending_tx_str = spending_tx.serialize().hex() 
            #assert test.nodes[0].testmempoolaccept([spending_tx_str])[0]['allowed']
            #assert test.nodes[0].test_transaction(spending_tx)
            # print("testmempoolaccept: ", test.nodes[0].testmempoolaccept([spending_tx_str]))
            # print("test_transaction: ",test.nodes[0].test_transaction(spending_tx))
            # print("Key path spending transaction weight: {}".format(test.nodes[0].decoderawtransaction(spending_tx_str)['weight']))
        else:
            # Construct transaction
            spending_tx = CTransaction()

            #spending_tx.nVersion = 2
            spending_tx.nLockTime = 0
            outpoint = COutPoint(tx.sha256, output_index)
            spending_tx_in = CTxIn(outpoint=outpoint)
            spending_tx.vin = [spending_tx_in]
            spending_tx.vout = [dest_output]

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
            _, musig_agg_ = generate_musig_key([pubkeys[i] for i in priority_order])
            tapscript_ = TapLeaf().construct_pk(musig_agg_)

            comb_ = None
            for comb in updated_combs:
                if comb[2] == musig_agg_:
                    comb_ = comb
                    break


            sighash = TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT, 0, scriptpath=True, script=tapscript_.script)
            witness_elements = []

            schnorr_nonces = list()
            for i in range(m):
                schnorr_nonces.append(generate_schnorr_nonce())


            R_agg, negated = aggregate_schnorr_nonces([schnorr_nonce.get_pubkey() for schnorr_nonce in schnorr_nonces])
            if negated:
                for schnorr_nonce in schnorr_nonces:
                    schnorr_nonce.negate()
            print(f"Script path witness_elements: ")
            sigs = list()
            for i in range(m):
                sigs.append(sign_musig(comb_[1][i], schnorr_nonces[i], R_agg, musig_agg_, sighash))


            
            sig_agg = aggregate_musig_signatures(sigs, R_agg)
            print(f"Aggregated musig signature: {sig_agg}")
            assert musig_agg_.verify_schnorr(sig_agg, sighash)
            witness_elements = [sig_agg, tapscript_.script, control_map[tapscript_.script]]
            for op in tapscript_.script:
                print(op.hex()) if isinstance(op, bytes) else print(op)
            print()
            print(f"{control_map[tapscript_.script].hex()}\n")
            spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))
            spending_tx_str = spending_tx.serialize().hex()

            # print("testmempoolaccept: ", test.nodes[0].testmempoolaccept([spending_tx_str]))
            # print("test_transaction: ",test.nodes[0].test_transaction(spending_tx))
            #print("Short delay script path spending transaction weight: {}".format(test.nodes[0].decoderawtransaction(spending_tx_str)['weight']))

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
