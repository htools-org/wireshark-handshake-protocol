-- SendHeaders Packet
local packet = {}

packet.name = "sendheaders"
packet.type = 12

packet.fields = {}

function packet.parse(protocol, tree, buffer, offset)
    -- No data
    return offset, nil
end

return packet
