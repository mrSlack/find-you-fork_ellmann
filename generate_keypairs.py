import os
import sys
from ecdsa import SigningKey, NIST224p
import plistlib

def generate_keypairs(num_pairs):
    pub_keys_c = []
    private_keys = []

    for _ in range(num_pairs):
        sk = SigningKey.generate(curve=NIST224p)
        vk = sk.get_verifying_key()
        
        pub_key = vk.to_string().hex()
        priv_key = sk.to_string().hex()
        
        pub_keys_c.append(f"0x{pub_key[:28]}, 0x{pub_key[28:]}")
        private_keys.append(priv_key)

    # Save public keys in C source code format
    with open("pub_keys_c.txt", "w") as pub_file:
        pub_file.write("const uint8_t pub_keys[][28] = {\n")
        for key in pub_keys_c:
            pub_file.write(f"    {{{key}}},\n")
        pub_file.write("};\n")

    # Save private keys in .plist format
    plist_dict = {f"key_{i}": key for i, key in enumerate(private_keys)}
    with open("accessory_list.plist", "wb") as plist_file:
        plistlib.dump(plist_dict, plist_file)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 generate_keypairs.py <number_of_keypairs>")
        sys.exit(1)

    num_pairs = int(sys.argv[1])
    generate_keypairs(num_pairs)
