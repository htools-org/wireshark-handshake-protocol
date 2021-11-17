-- Unknown Packet
local packet = {}

packet.name = "unknown"
packet.type = 30

packet.fields = {
    data = ProtoField.bytes("handshake.unknown.data", "Data", base.NONE)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Data
    local length = buffer:len() - offset
    local data_buf = buffer(offset, length)
    tree:add_le(packet.fields.data, data_buf)
    offset = offset + length

    -- Info column string
    local info = "data=" .. data_buf:range(0, math.min(length, 6)) .. "..."

    return offset, info
end

return packet
