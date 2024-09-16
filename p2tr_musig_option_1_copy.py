# Imports
from io import BytesIO
import util
from test_framework.address import program_to_witness
from test_framework.key import generate_key_pair, generate_bip340_key_pair, generate_bip340_key_pair_from_xprv, generate_schnorr_nonce, ECKey, ECPubKey, SECP256K1_FIELD_SIZE, SECP256K1, SECP256K1_ORDER
from test_framework.messages import CTxInWitness, sha256, CTransaction, COutPoint, CTxIn, CTxOut
from test_framework.musig import aggregate_musig_signatures, aggregate_schnorr_nonces, generate_musig_key, musig_digest, sign_musig
from test_framework.script import *
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

def p2tr_musig_option_1_copy(logger=False):
    
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

        for i in range(n):
            #### For generating key pair using extended private key using HD wallet:
            # _xprivkey = input(f"Enter extended private key for cosigner {i+1}:")
            # _path = input(f"Enter the derivation path for cosigner {i+1}. If you are not sure what this is, leave this field unchanged.")
            # if(len(_path) == 0):
            #     _path = "m//49'/1'/0'/0/{}".format(i+1)
            # _privkey, _pubkey = generate_bip340_key_pair_from_xprv(_xprivkey,_path)

            #### For trial, generate keys randomly using following code:
            _privkey, _pubkey = generate_bip340_key_pair()
            privkeys.append(_privkey)
            pubkeys.append(_pubkey)

        print(f"\nFollowing are the generated {n} public and private keys.", end='\n\n')
        for idx, pk, privk in zip([i + 1 for i in range(n)], pubkeys, privkeys):
            print(f"Public Key {idx}: {pk}")
            # print(f"Private Key {idx}: {privk}")
            print(f"Size of Public Key {idx} is: {len(pk.get_bytes())} bytes", end='\n\n')

        
        c_map, musig_agg = generate_musig_key(pubkeys)
        privkeys_c = deepcopy(privkeys)
        for i in range(n):
            privkeys_c[i] = privkeys[i].mul(c_map[pubkeys[i]])

        if musig_agg.get_y()%2 != 0:
            musig_agg.negate()
            for i in range(n):
                privkeys_c[i].negate()

        logger.warning(f"MuSig pubkey: {musig_agg.get_bytes().hex()}")
        print(f"Size of Aggregated Public Key is: {len(musig_agg.get_bytes())} bytes", end='\n\n')

        # tapscript_1 = TapLeaf().construct_csa(m, pubkeys)
        # # Construct taptree with huffman constructor
        # tapscript_weights = [(1, tapscript_1)]
        # multisig_taproot = TapTree(key = musig_agg, root=None)
        # multisig_taproot.huffman_constructor(tapscript_weights)

        # print(f"Taproot descriptor: {multisig_taproot.desc}\n")
        # print(f"taproot script: {multisig_taproot.root.script}")
        # for op in multisig_taproot.root.script:
        #     if isinstance(op, bytes):
        #         print(op.hex())
        #     else:
        #         print(op)
        # print("\nSatisfying witness elements:")
        # for element, value in multisig_taproot.root.sat:
        #     print("{}, {}".format(element, value.hex()))
            
        # Derive segwit v1 address
        tapscript, taptweak, control_map = taproot_construct(musig_agg)
        # taptweak = int.from_bytes(taptweak, 'big')
        # output_pubkey = musig_agg
        # # output_pubkey = musig_agg
        output_pubkey_b = musig_agg.get_bytes()
        segwit_address = program_to_witness(1, output_pubkey_b)
        logger.warning(f"Segwit Address: {segwit_address}")

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

        print(f"Segwit v1 output is {output}")

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
            if output_keyPath.get_y() % 2 != 0:
                output_keyPath.negate()
                for i in range(n):
                    privkeys_c[i].negate()
                tweak_keyPath = SECP256K1_ORDER - taptweak

            # Create sighash for ALL
            sighash_musig = TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT)
            
            # Generate individual nonces for participants and an aggregate nonce point
            noncelist = list()
            noncepointlist = list()
            for i in range(n):
                noncelist.append(generate_schnorr_nonce())
                noncepointlist.append(noncelist[i].get_pubkey())

            R_agg, negated = aggregate_schnorr_nonces(noncepointlist)
            if negated:
                for i in range(n):
                    noncelist[i].negate()

            # Create an aggregate signature.
            sigs = list()
            for i in range(n):
                sigs.append(sign_musig(privkeys_c[i], noncelist[i], R_agg, output_pubkey, sighash_musig))
            e = musig_digest(R_agg, output_keyPath, sighash_musig)
            sigs.append(e * tweak_keyPath)
            sig_agg = aggregate_musig_signatures(sigs, R_agg)
            
            print(f"Aggregate signature is {sig_agg.hex()}\n")

            assert output_keyPath.verify_schnorr(sig_agg, sighash_musig)

            # Construct transaction witness
            spending_tx.wit.vtxinwit.append(CTxInWitness([sig_agg]))
            
            print(f"spending_tx: {spending_tx}\n")

            # Test mempool acceptance
            spending_tx_str = spending_tx.serialize().hex() 
            #assert test.nodes[0].testmempoolaccept([spending_tx_str])[0]['allowed']
            #assert test.nodes[0].test_transaction(spending_tx)
            print("testmempoolaccept: ", test.nodes[0].testmempoolaccept([spending_tx_str]))
            print("test_transaction: ",test.nodes[0].test_transaction(spending_tx))
            print("Key path spending transaction weight: {}".format(test.nodes[0].decoderawtransaction(spending_tx_str)['weight']))
        else:
            # Construct transaction
            spending_tx = CTransaction()

            #spending_tx.nVersion = 2
            spending_tx.nLockTime = 0
            outpoint = COutPoint(tx.sha256, output_index)
            spending_tx_in = CTxIn(outpoint=outpoint)
            spending_tx.vin = [spending_tx_in]
            spending_tx.vout = [dest_output]

            sighash = TaprootSignatureHash(spending_tx, [output], SIGHASH_ALL_TAPROOT, 0, scriptpath=True, script=tapscript_1.script)

            witness_elements = []

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

            for i in priority_order:
                sigs[i] = privkeys[i].sign_schnorr(sighash)

            # Add witness to transaction
            reversed_sigs = list(reversed(sigs))
            # print("reversed_sigs: ",reversed_sigs)
            for sig in reversed_sigs:
                witness_elements.append(sig)
            witness_elements.append(tapscript_1.script)
            witness_elements.append(control_map[tapscript_1.script])
            print("witness_elements: ", witness_elements)

            spending_tx.wit.vtxinwit.append(CTxInWitness(witness_elements))
            spending_tx_str = spending_tx.serialize().hex()

            print("testmempoolaccept: ", test.nodes[0].testmempoolaccept([spending_tx_str]))
            print("test_transaction: ",test.nodes[0].test_transaction(spending_tx))
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
