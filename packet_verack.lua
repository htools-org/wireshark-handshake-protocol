-- Verack Packet
local packet = {}

packet.name = "verack"
packet.type = 1

packet.fields = {}

function packet.parse(protocol, tree, buffer, offset)
    -- No data
    return offset, nil
end

return packet
