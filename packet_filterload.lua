-- FilterLoad Packet
local packet = {}

packet.name = "filterload"
packet.type = 17

packet.fields = {
    filter = ProtoField.bytes("handshake.filter.filter", "Bloom Filter",
                              base.NONE),
    size = ProtoField.uint32("handshake.filter.size", "Filter Size", base.DEC),
    n = ProtoField.uint32("handshake.filter.n", "N", base.DEC),
    tweak = ProtoField.uint32("handshake.filter.tweak", "Tweak", base.DEC),
    update = ProtoField.uint8("handshake.filter.update", "Update", base.DEC)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Filter length
    local length_size, length_value = utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.size, buffer(offset, length_size)) --
    :append_text(" bytes")
    offset = offset + length_size

    -- Filter
    tree:add_le(packet.fields.filter, buffer(offset, length_value))
    offset = offset + length_value

    -- N
    local n_buf = buffer(offset, 4)
    tree:add_le(packet.fields.n, n_buf)
    offset = offset + 4

    -- Tweak
    local tweak_buf = buffer(offset, 4)
    tree:add_le(packet.fields.tweak, tweak_buf)
    offset = offset + 4

    -- Update
    local update_buf = buffer(offset, 1)
    tree:add_le(packet.fields.update, update_buf)
    offset = offset + 1

    -- Info column string
    local info = "n=" .. n_buf:le_uint() .. " tweak=" .. tweak_buf:le_uint() ..
                     " update=" .. update_buf:le_uint()

    return offset, info
end

return packet
