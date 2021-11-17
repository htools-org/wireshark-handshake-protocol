-- GetBlocks Packet
local packet = {}

packet.name = "getblocks"
packet.type = 9

packet.fields = {
    count = ProtoField.uint64("handshake.getblocks.count", "Hash Count",
                              base.DEC),
    hash = ProtoField.bytes("handshake.getblocks.hash", "Hash", base.NONE),
    stop = ProtoField.bytes("handshake.getblocks.stop", "Stop", base.NONE)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Hash count
    local count_size, count_value = utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.count, buffer(offset, count_size))
    offset = offset + count_size

    -- Loop for every hash
    for i = 0, count_value - 1, 1 do
        tree:add_le(packet.fields.hash, buffer(offset, 32))
        offset = offset + 32
    end

    -- Stop
    tree:add_le(packet.fields.stop, buffer(offset, 32))
    offset = offset + 32

    -- Info column string
    local info = "block_locator_hashes=" .. count_value

    return offset, info
end

return packet
