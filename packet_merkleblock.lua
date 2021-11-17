local HeadersPacket = require("handshake.packet_headers")
local BlockPacket = require("handshake.packet_block")

-- MerkleBlock Packet
local packet = {}

packet.name = "merkleblock"
packet.type = 20

packet.fields = {
    hash_count = ProtoField.uint64("handshake.block.hash.count", "Hash Count",
                                   base.DEC),
    hash = ProtoField.bytes("handshake.block.hash", "Hash", base.NONE),
    flags_length = ProtoField.uint64("handshake.block.flags.length",
                                     "Flags Length", base.DEC),
    flags = ProtoField.bytes("handshake.block.flags", "Flags", base.NONE)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Block Header
    local hSubtree = tree:add(protocol,
                              buffer(offset, constants.BLOCK_HEADER_LEN),
                              "Block Header")

    offset = HeadersPacket.parse_header(protocol, hSubtree, buffer, offset)

    -- Tx count
    local txcount_buf = buffer(offset, 4)
    tree:add_le(BlockPacket.fields.txcount, txcount_buf)
    offset = offset + 4

    -- Hash count
    local itemscount_size, itemscount_value =
        utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.hash_count, buffer(offset, itemscount_size))
    offset = offset + itemscount_size

    -- Hashes
    local hashesSubtree = tree:add(protocol,
                                   buffer(offset, itemscount_value * 32),
                                   "Hashes")
    for i = 0, itemscount_value - 1, 1 do
        hashesSubtree:add_le(packet.fields.hash, buffer(offset, 32))
        offset = offset + 32
    end

    -- Flag length
    local flaglength_size, flaglength_value =
        utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.flags_length, buffer(offset, flaglength_size)) --
    :append_text(" bytes")
    offset = offset + flaglength_size

    -- Flag
    local flags_buf = buffer(offset, flaglength_value)
    tree:add_le(packet.fields.flags, flags_buf)
    offset = offset + flaglength_value

    -- Info column string
    local info = "hashes=" .. itemscount_value .. " flags=" .. flags_buf

    return offset, info
end

return packet
