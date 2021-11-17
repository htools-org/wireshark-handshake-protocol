-- FeeFilter Packet
local packet = {}

packet.name = "feefilter"
packet.type = 21

packet.fields = {
    rate = ProtoField.int64("handshake.feefilter.rate", "Rate", base.DEC)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Rate
    local rate_buf = buffer(offset, 8)
    tree:add_le(packet.fields.rate, rate_buf)
    offset = offset + 8

    -- Info column string
    local info = "rate=" .. rate_buf:le_int64()

    return offset, info
end

return packet
