-- GetBlockTxn Packet (BIP-152)
local packet = {}

packet.name = "getblocktxn"
packet.type = 24

packet.fields = {
    hash = ProtoField.bytes("handshake.bip152.hash", "Hash", base.NONE),
    indexcount = ProtoField.uint64("handshake.bip152.indexcount", "Index Count",
                                   base.DEC),
    index = ProtoField.uint64("handshake.bip152.index", "Index", base.DEC)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Hash
    local hash_buf = buffer(offset, 32)
    tree:add_le(packet.fields.hash, hash_buf)
    offset = offset + 32

    -- Index count
    local itemscount_size, itemscount_value =
        utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.indexcount, buffer(offset, itemscount_size))
    offset = offset + itemscount_size

    -- Indexes
    for i = 0, itemscount_value - 1, 1 do
        local indexlength_size, indexlength_value =
            utils.get_varint_value(buffer, offset)
        tree:add_le(packet.fields.index, buffer(offset, indexlength_size)) --
        :append_text(" bytes")
        offset = offset + indexlength_size
    end

    -- Info column string
    local info = "hash=..." .. hash_buf:range(28, 4) .. " indexes=" ..
                     itemscount_value

    return offset, info
end

return packet
