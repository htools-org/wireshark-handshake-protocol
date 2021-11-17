-- SendCmpct Packet
local packet = {}

packet.name = "sendcmpct"
packet.type = 22

packet.fields = {
    mode = ProtoField.uint8("handshake.sendcmpct.mode", "Mode", base.DEC),
    version = ProtoField.uint64("handshake.sendcmpct.version", "Version",
                                base.DEC)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Mode
    local mode_buf = buffer(offset, 1)
    local mode = constants.SENDCMPCT_MODE_BY_VAL[mode_buf:le_uint()]
    tree:add_le(packet.fields.mode, mode_buf) --
    :append_text(" (" .. mode .. ")")
    offset = offset + 1

    -- Version
    local version_buf = buffer(offset, 8)
    tree:add_le(packet.fields.version, version_buf)
    offset = offset + 8

    -- Info column string
    local info = "version=" .. version_buf:le_uint64() .. " mode=" .. mode

    return offset, info
end

return packet
