"""
Shared constants for proxy detection.

EIP-1967 slots: keccak256(slot_name) - 1
EIP-1822 slot: keccak256("PROXIABLE")
"""

# EIP-1967 storage slots (keccak256 - 1 per spec)
# https://eips.ethereum.org/EIPS/eip-1967
EIP1967_IMPL_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
EIP1967_BEACON_SLOT = "0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50"

# EIP-1822 (UUPS) storage slot
# https://eips.ethereum.org/EIPS/eip-1822
EIP1822_IMPL_SLOT = "0xc5f16f0fcc639fa48a6947836d9850f504798523bf8c9a3a87d5876cf622bcf7"

# Diamond (EIP-2535) storage slot
# keccak256("diamond.standard.diamond.storage") - varies by implementation
DIAMOND_STORAGE_SLOT = "0xc8fcad8db84d3cc18b4c41d551ea0ee66dd599cde068d998e57d5e09332c131c"

# Gnosis Safe singleton slot (slot 0)
GNOSIS_SINGLETON_SLOT = "0x0000000000000000000000000000000000000000000000000000000000000000"

# EIP-1167 minimal proxy bytecode patterns
EIP1167_PREFIX = bytes.fromhex("363d3d373d3d3d363d73")
EIP1167_SUFFIX = bytes.fromhex("5af43d82803e903d91602b57fd5bf3")

# Common proxy function selectors
IMPLEMENTATION_SELECTOR = "0x5c60da1b"  # implementation()
