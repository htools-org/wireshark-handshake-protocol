-- Ping Packet
local packet = {}

packet.name = "ping"
packet.type = 2

packet.fields = {
    nonce = ProtoField.uint64("handshake.ping.nonce", "Nonce", base.HEX)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Nonce
    local nonce_buf = buffer(offset, 8)
    tree:add_le(packet.fields.nonce, nonce_buf)
    offset = offset + 8

    -- Info column string
    local info = "nonce=" .. nonce_buf

    return offset, info
end

return packet
