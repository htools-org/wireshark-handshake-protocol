-- Claim Packet
local packet = {}

packet.name = "claim"
packet.type = 28

packet.fields = {
    size = ProtoField.uint16("handshake.claim.size", "Size", base.DEC),
    blob = ProtoField.bytes("handshake.claim.blob", "Blob", base.NONE)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Size
    local size_buf = buffer(offset, 2)
    local size = size_buf:le_uint()
    tree:add_le(packet.fields.size, size_buf)
    offset = offset + 2

    -- Blob
    tree:add_le(packet.fields.blob, buffer(offset, size))
    offset = offset + size

    -- Info column string
    local info = "size=" .. size

    return offset, info
end

return packet
