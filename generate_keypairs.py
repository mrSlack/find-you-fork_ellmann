import os
import sys
from ecdsa import SigningKey, NIST224p
import plistlib

def generate_keypairs(num_pairs):
    pub_keys_c = []
    private_keys = []

    for _ in range(num_pairs):
        sk = SigningKey.generate(curve=NIST224p)
        vk = sk.verifying_key
        
        # Get the x coordinate of the uncompressed public key (28 bytes)
        pub_key = vk.to_string()[:28]
        priv_key = sk.to_string().hex()
        
        # Format the public key for C source code
        formatted_pub_key = ', '.join([f"0x{pub_key[i]:02x}" for i in range(len(pub_key))])
        pub_keys_c.append(formatted_pub_key)
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
