-- Mempool Packet
local packet = {}

packet.name = "mempool"
packet.type = 16

packet.fields = {}

function packet.parse(protocol, tree, buffer, offset)
    -- No data
    return offset, nil
end

return packet
