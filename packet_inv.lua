-- Inv Packet
local packet = {}

packet.name = "inv"
packet.type = 6

packet.fields = {
    count = ProtoField.uint64("handshake.inv.count", "Item Count", base.DEC),
    type = ProtoField.uint32("handshake.inv.type", "Inventory Type", base.DEC),
    hash = ProtoField.bytes("handshake.inv.hash", "Hash", base.NONE)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Item count
    local count_size, count_value = utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.count, buffer(offset, count_size))
    offset = offset + count_size

    -- Loop for every item
    for i = 0, count_value - 1, 1 do
        local invSubtree = tree:add(protocol, buffer(offset, 36),
                                    "Inv Item " .. i + 1)

        -- Inventory item type
        local type_buf = buffer(offset, 4)
        invSubtree:add_le(packet.fields.type, type_buf) --
        :append_text(" (" .. constants.INV_TYPE_BY_VAL[type_buf:le_uint()] ..
                         ")")
        offset = offset + 4

        -- Inventory item Hash
        invSubtree:add_le(packet.fields.hash, buffer(offset, 32))
        offset = offset + 32
    end

    -- Info column string
    local info = "inventory_items=" .. count_value

    return offset, info
end

return packet
