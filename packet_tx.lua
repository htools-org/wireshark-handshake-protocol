local utils = require("handshake.utils")

-- Tx Packet
local packet = {}

packet.name = "tx"
packet.type = 14

packet.fields = {
    version = ProtoField.uint32("handshake.tx.version", "Version", base.DEC),
    incount = ProtoField.uint32("handshake.tx.incount", "Input Count", base.DEC),
    outcount = ProtoField.uint32("handshake.tx.outcount", "Output Count",
                                 base.DEC),
    locktime = ProtoField.uint32("handshake.tx.locktime", "Locktime", base.DEC),
    input_prevout_hash = ProtoField.bytes("handshake.tx.input.prevout.hash",
                                          "Hash", base.NONE),
    input_prevout_index = ProtoField.uint32("handshake.tx.input.prevout.index",
                                            "Index", base.DEC),
    input_sequence = ProtoField.uint32("handshake.tx.input.sequence",
                                       "Sequence", base.DEC),
    output_value = ProtoField.uint64("handshake.tx.output.value", "Value",
                                     base.DEC),
    output_address_version = ProtoField.uint8(
        "handshake.tx.output.address.version", "Address Version", base.DEC),
    output_address_size = ProtoField.uint8("handshake.tx.output.address.size",
                                           "Address Size", base.DEC),
    output_address_hash = ProtoField.bytes("handshake.tx.output.address.hash",
                                           "Address Hash", base.NONE),
    output_covenant_count = ProtoField.uint64(
        "handshake.tx.output.covenant.count", "Covenant Items Count", base.DEC),
    output_covenant_type = ProtoField.uint8("handshake.tx.output.covenant.type",
                                            "Type", base.DEC),
    output_covenant_item = ProtoField.bytes("handshake.tx.output.covenant.item",
                                            "Item", base.NONE),
    output_witness_item_count = ProtoField.uint64(
        "handshake.tx.output.witness.item.count", "Witness Items Count",
        base.DEC),
    output_witness_item = ProtoField.bytes("handshake.tx.output.witness.item",
                                           "Witness Item", base.NONE),
    output_witness_item_length = ProtoField.uint64(
        "handshake.tx.output.witness.item.length", "Witness Item Length",
        base.DEC)
}

function packet.get_covenant_item(type, idx, item_buf)

    -- NameHash is always first
    if idx == 0 then return "(name hash)" end

    -- Height is always at index 1 for all except NONE covenant
    if idx == 1 and type ~= 0 then
        return "(height: " .. item_buf:le_uint() .. ")"
    end

    if idx == 2 then
        -- CLAIM, OPEN, BID, FINALIZE
        if type == 1 or type == 2 or type == 3 or type == 10 then
            return "(name: " .. item_buf:string() .. ")"
        end

        -- REVEAL
        if type == 4 then return "(nonce)" end

        -- REGISTER, UPDATE
        if type == 6 or type == 7 then return "(record data)" end

        -- RENEW
        if type == 8 then return "(block hash)" end
    end

    if idx == 3 then

        -- CLAIM, FINALIZE
        if type == 1 or type == 10 then return "(flags)" end

        -- BID
        if type == 3 then return "(hash)" end

        -- REIGSTER
        if type == 6 then return "(block hash)" end

        -- TRANSFER
        if type == 9 then return "(address)" end
    end

    -- Only FINALIZE from here onwards

    if idx == 4 then return "(claim height: " .. item_buf:le_uint() .. ")" end

    if idx == 5 then return "(renewal count: " .. item_buf:le_uint() .. ")" end

    if idx == 6 then return "(block hash)" end

    return ""
end

function packet.parse_covenant(protocol, tree, buffer, offset)
    local covenant_type_buf = buffer(offset, 1)
    local covenant_type = covenant_type_buf:le_uint()
    offset = offset + 1

    tree:add(packet.fields.output_covenant_type, covenant_type_buf) --
    :append_text(" (" .. constants.COVENANT_TYPE_BY_VAL[covenant_type] .. ")")

    -- Covenant items count
    local covitemscount_size, covitemscount_value =
        utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.output_covenant_count,
                buffer(offset, covitemscount_size))
    offset = offset + covitemscount_size

    -- Covenant items
    for j = 0, covitemscount_value - 1, 1 do
        local itemlen_size, itemlen_value =
            utils.get_varint_value(buffer, offset)
        offset = offset + itemlen_size
        local item_buf = buffer(offset, itemlen_value)
        tree:add_le(packet.fields.output_covenant_item, item_buf) --
        
            :append_text(
                " " .. packet.get_covenant_item(covenant_type, j, item_buf))
        offset = offset + itemlen_value
    end

    return offset
end

function packet.parse_tx(protocol, tree, buffer, offset)
    -- Version
    tree:add_le(packet.fields.version, buffer(offset, 4))
    offset = offset + 4

    -- Input count
    local incount_size, incount_value = utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.incount, buffer(offset, incount_size))
    offset = offset + incount_size

    -- Inputs
    for i = 0, incount_value - 1, 1 do
        local inputSubtree = tree:add(protocol, buffer(offset, 40),
                                      "Input " .. i)
        inputSubtree:add_le(packet.fields.input_prevout_hash, buffer(offset, 32))
        inputSubtree:add_le(packet.fields.input_prevout_index,
                            buffer(offset + 32, 4))
        inputSubtree:add_le(packet.fields.input_sequence, buffer(offset + 36, 4))
        offset = offset + 40
    end

    -- Output count
    local outcount_size, outcount_value = utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.outcount, buffer(offset, outcount_size))
    offset = offset + outcount_size

    -- Outputs
    for i = 0, outcount_value - 1, 1 do
        -- Keep track of where it starts
        local offset_output_start = offset
        local outSubtree = tree:add(protocol, buffer(offset), "Output " .. i)

        outSubtree:add_le(packet.fields.output_value, buffer(offset, 8))
        offset = offset + 8

        -- Address
        local offset_address_start = offset
        local addrSubtree = outSubtree:add(protocol, buffer(offset), "Address")
        addrSubtree:add_le(packet.fields.output_address_version,
                           buffer(offset, 1))
        offset = offset + 1

        local hash_size_buf = buffer(offset, 1)
        local hash_size = hash_size_buf:le_uint()
        addrSubtree:add_le(packet.fields.output_address_size, hash_size_buf)
        offset = offset + 1

        addrSubtree:add_le(packet.fields.output_address_hash,
                           buffer(offset, hash_size))
        offset = offset + hash_size

        addrSubtree.len = offset - offset_address_start

        -- Covenant
        local covSubtree = outSubtree:add(protocol, buffer(offset), "Covenant")
        local offset_covenant_start = offset
        offset = packet.parse_covenant(protocol, covSubtree, buffer, offset)
        covSubtree.len = offset - offset_covenant_start

        outSubtree.len = offset - offset_output_start
    end

    tree:add_le(packet.fields.locktime, buffer(offset, 4))
    offset = offset + 4

    -- Witness (one for every input)
    for i = 0, incount_value - 1, 1 do
        local offset_witness_start = offset
        local witSubtree = tree:add(protocol, buffer(offset),
                                    "Witness for input " .. i)

        -- Witness item count
        local wititemscount_size, wititemscount_value =
            utils.get_varint_value(buffer, offset)
        witSubtree:add_le(packet.fields.output_witness_item_count,
                          buffer(offset, wititemscount_size))
        offset = offset + wititemscount_size

        -- Witness items
        for j = 0, wititemscount_value - 1, 1 do
            local itemlen_size, itemlen_value =
                utils.get_varint_value(buffer, offset)
            witSubtree:add_le(packet.fields.output_witness_item_length,
                              buffer(offset, itemlen_size))
                :append_text(" bytes")
            offset = offset + itemlen_size
            witSubtree:add_le(packet.fields.output_witness_item,
                              buffer(offset, itemlen_value))
            offset = offset + itemlen_value
        end

        witSubtree.len = offset - offset_witness_start
    end

    -- Info column string
    local info = "inputs=" .. incount_value .. " outputs=" .. outcount_value

    return offset, info
end

function packet.parse(protocol, tree, buffer, offset)
    offset, info = packet.parse_tx(protocol, tree, buffer, offset)
    return offset, info
end

return packet
