-- Header
local header = {}

header.fields = {
    magic = ProtoField.uint32("handshake.magic", "Packet Magic", base.HEX),
    type = ProtoField.uint32("handshake.type", "Packet Type", base.DEC),
    payload_length = ProtoField.uint32("handshake.length", "Payload Length",
                                       base.DEC)
}

function header.parse(protocol, tree, buffer, offset)
    -- Magic
    local magic_buf = buffer(offset, 4)
    local magic = constants.MAGIC_NETWORK[magic_buf:le_uint()]
    tree:add(header.fields.magic, magic_buf) --
    :append_text(" (" .. magic .. ")")
    offset = offset + 4

    -- Payload/Packet type
    local type_buf = buffer(offset, 1)
    local type = constants.PAYLOAD_TYPE_BY_VAL[type_buf:le_uint()]
    tree:add(header.fields.type, type_buf) --
    :append_text(" (" .. type .. ")")
    offset = offset + 1

    -- Payload length
    local payload_len_buf = buffer(offset, 4)
    tree:add_le(header.fields.payload_length, payload_len_buf) --
    :append_text(" bytes")
    offset = offset + 4

    return offset, type_buf:le_uint(), payload_len_buf:le_uint()
end

return header
