constants = {}

constants.PACKET_HEADER_LEN = 9
constants.BLOCK_HEADER_LEN = 236

constants.MAGIC_NETWORK = {
    [1533997779] = "mainnet",
    [2974944722] = "testnet",
    [2922943951] = "regtest",
    [241471196] = "simnet"
}

constants.PAYLOAD_TYPE_BY_VAL = {
    [0] = "VERSION",
    [1] = "VERACK",
    [2] = "PING",
    [3] = "PONG",
    [4] = "GETADDR",
    [5] = "ADDR",
    [6] = "INV",
    [7] = "GETDATA",
    [8] = "NOTFOUND",
    [9] = "GETBLOCKS",
    [10] = "GETHEADERS",
    [11] = "HEADERS",
    [12] = "SENDHEADERS",
    [13] = "BLOCK",
    [14] = "TX",
    [15] = "REJECT",
    [16] = "MEMPOOL",
    [17] = "FILTERLOAD",
    [18] = "FILTERADD",
    [19] = "FILTERCLEAR",
    [20] = "MERKLEBLOCK",
    [21] = "FEEFILTER",
    [22] = "SENDCMPCT",
    [23] = "CMPCTBLOCK",
    [24] = "GETBLOCKTXN",
    [25] = "BLOCKTXN",
    [26] = "GETPROOF",
    [27] = "PROOF",
    [28] = "CLAIM",
    [29] = "AIRDROP",
    [30] = "UNKNOWN",
    [31] = "INTERNAL",
    [32] = "DATA"
}

constants.INV_TYPE_BY_VAL = {
    [0] = "TX",
    [1] = "BLOCK",
    [2] = "FILTERED_BLOCK",
    [3] = "CMPCT_BLOCK",
    [4] = "CLAIM",
    [5] = "AIRDROP"
}

constants.COVENANT_TYPE_BY_VAL = {
    [0] = "NONE",
    [1] = "CLAIM",
    [2] = "OPEN",
    [3] = "BID",
    [4] = "REVEAL",
    [5] = "REDEEM",
    [6] = "REGISTER",
    [7] = "UPDATE",
    [8] = "RENEW",
    [9] = "TRANSFER",
    [10] = "FINALIZE",
    [11] = "REVOKE"
}

constants.REJECT_CODE_BY_VAL = {
    [0x01] = 'MALFORMED',
    [0x10] = 'INVALID',
    [0x11] = 'OBSOLETE',
    [0x12] = 'DUPLICATE',
    [0x40] = 'NONSTANDARD',
    [0x41] = 'DUST',
    [0x42] = 'INSUFFICIENTFEE',
    [0x43] = 'CHECKPOINT',
    [0x100] = 'INTERNAL',
    [0x101] = 'HIGHFEE',
    [0x102] = 'ALREADYKNOWN',
    [0x103] = 'CONFLICT'
}

constants.SENDCMPCT_MODE_BY_VAL = {
    [0] = "Low Bandwidth Relaying mode",
    [1] = "High Bandwidth Relaying mode"
}

constants.PROOF_NODE_TYPE_BY_VAL = {
    [0] = "TYPE_DEADEND",
    [1] = "TYPE_SHORT",
    [2] = "TYPE_COLLISION",
    [3] = "TYPE_EXISTS",
    [4] = "TYPE_UNKNOWN"
}

return constants
