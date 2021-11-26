local HeadersPacket = require("handshake.packet_headers")
local BlockPacket = require("handshake.packet_block")
local TxPacket = require("handshake.packet_tx")

-- CmpctBlock Packet
local packet = {}

packet.name = "cmpctblock"
packet.type = 23

packet.fields = {
    key_nonce = ProtoField.bytes("handshake.cmpctblock.key_nonce", "Key Nonce",
                                 base.NONE),
    id_count = ProtoField.uint64("handshake.cmpctblock.idcount", "ID Count",
                                 base.DEC),
    id_lo = ProtoField.uint32("handshake.cmpctblock.id.lo", "ID Lo", base.DEC),
    id_hi = ProtoField.uint16("handshake.cmpctblock.id.hi", "ID Hi", base.DEC),
    tx_index = ProtoField.uint64("handshake.cmpctblock.tx_index", "Tx index",
                                 base.DEC)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Block Header
    local hSubtree = tree:add(protocol,
                              buffer(offset, constants.BLOCK_HEADER_LEN),
                              "Block Header")

    offset = HeadersPacket.parse_header(protocol, hSubtree, buffer, offset)

    -- Key Nonce
    tree:add_le(packet.fields.key_nonce, buffer(offset, 8))
    offset = offset + 8

    -- ID count
    local idcount_size, idcount_value = utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.id_count, buffer(offset, idcount_size))
    offset = offset + idcount_size

    -- IDs
    local idsSubtree = tree:add(protocol, buffer(offset, idcount_value), "IDs")
    for i = 0, idcount_value - 1, 1 do
        local lo_buf = buffer(offset, 4)
        local lo = lo_buf:le_uint()
        offset = offset + 4

        local hi_buf = buffer(offset, 2)
        local hi = hi_buf:le_uint()
        offset = offset + 2

        idsSubtree:add_le(packet.fields.id_lo, lo_buf)
        idsSubtree:add_le(packet.fields.id_hi, hi_buf)
    end

    -- Tx count
    local txcount_size, txcount_value = utils.get_varint_value(buffer, offset)
    tree:add_le(BlockPacket.fields.txcount, buffer(offset, txcount_size))
    offset = offset + txcount_size

    -- Note when tx starts
    local offset_txs_start = offset

    local txsSubtree = tree:add(protocol, buffer(offset), "Transactions")

    -- Loop for every transaction
    for tx_idx = 0, txcount_value - 1, 1 do

        -- Tx index
        local txidx_size, txidx_value = utils.get_varint_value(buffer, offset)
        txsSubtree:add_le(packet.fields.tx_index, buffer(offset, txidx_size))
        offset = offset + txidx_size

        -- Note when tx starts
        local offset_tx_start = offset

        local txSubtree = txsSubtree:add(protocol, buffer(offset),
                                         "Transaction at index " .. txidx_value)

        offset = TxPacket.parse_tx(protocol, txSubtree, buffer, offset)

        txSubtree.len = offset - offset_tx_start
    end

    txsSubtree.len = offset - offset_txs_start

    -- Info column string
    local info = "ids=" .. idcount_value .. " txs=" .. txcount_value

    return offset, info
end

return packet
