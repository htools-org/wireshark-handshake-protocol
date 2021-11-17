-- GetAddr Packet
local packet = {}

packet.name = "getaddr"
packet.type = 4

packet.fields = {}

function packet.parse(protocol, tree, buffer, offset)
    -- No data
    return offset, nil
end

return packet
