-- FilterClear Packet
local packet = {}

packet.name = "filterclear"
packet.type = 19

packet.fields = {}

function packet.parse(protocol, tree, buffer, offset)
    -- No data
    return offset, nil
end

return packet
