-- FilterAdd Packet
local packet = {}

packet.name = "filteradd"
packet.type = 18

packet.fields = {
    size = ProtoField.uint64("handshake.filteradd.size", "Size", base.DEC),
    data = ProtoField.bytes("handshake.filteradd.data", "Data", base.NONE)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Size
    local datalen_size, datalen_value = utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.size, buffer(offset, datalen_size))
    offset = offset + datalen_size

    -- Data
    tree:add_le(packet.fields.data, buffer(offset, datalen_value))
    offset = offset + datalen_value

    -- Info column string
    local info = "size=" .. datalen_value

    return offset, info
end

return packet
