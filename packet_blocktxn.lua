local TxPacket = require("handshake.packet_tx")

-- BlockTxn Packet (BIP-152)
local packet = {}

packet.name = "blocktxn"
packet.type = 25

packet.fields = {
    hash = ProtoField.bytes("handshake.bip152.hash", "Hash", base.NONE),
    txcount = ProtoField.uint64("handshake.bip152.txcount", "Tx Count", base.DEC)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Hash
    local hash_buf = buffer(offset, 32)
    tree:add_le(packet.fields.hash, hash_buf)
    offset = offset + 32

    -- Tx count
    local txcount_size, txcount_value = utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.txcount, buffer(offset, txcount_size))
    offset = offset + txcount_size

    -- Loop for every transaction
    for tx_idx = 0, txcount_value - 1, 1 do

        -- Note when it starts
        local offset_tx_start = offset

        local txSubtree = tree:add(protocol, buffer(offset),
                                   "Transaction " .. tx_idx)

        offset = TxPacket.parse_tx(protocol, txSubtree, buffer, offset)

        txSubtree.len = offset - offset_tx_start
    end

    -- Info column string
    local info = "hash=..." .. hash_buf:range(28, 4) .. " txcount=" ..
                     txcount_value

    return offset, info
end

return packet
