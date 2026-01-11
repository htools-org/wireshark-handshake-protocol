-- Proof Packet
local packet = {}

packet.name = "proof"
packet.type = 27

packet.fields = {
    root = ProtoField.bytes("handshake.proof.root", "Root", base.NONE),
    key = ProtoField.bytes("handshake.proof.key", "Key", base.NONE),

    -- Proof fields
    field = ProtoField.uint16("handshake.proof.field", "Field", base.DEC),
    count = ProtoField.uint16("handshake.proof.count", "Count", base.DEC),
    type = ProtoField.uint32("handshake.proof.type", "Type", base.DEC),
    prefixes_bitfield = ProtoField.bytes("handshake.proof.count",
                                         "Prefixes Bitfield", base.BIN),
    proofnode = ProtoField.bytes("handshake.proof.proofnode", "ProofNode",
                                 base.NONE),
    prefix_size = ProtoField.uint16("handshake.proof.prefix_size",
                                    "Prefix Size", base.DEC),
    left = ProtoField.bytes("handshake.proof.left", "Left", base.NONE),
    right = ProtoField.bytes("handshake.proof.right", "Right", base.NONE),
    hash = ProtoField.bytes("handshake.proof.hash", "Hash", base.NONE),
    size = ProtoField.uint16("handshake.proof.size", "Size", base.DEC),
    value = ProtoField.bytes("handshake.proof.value", "Value", base.NONE)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Root
    local root_buf = buffer(offset, 32)
    tree:add_le(packet.fields.root, root_buf)
    offset = offset + 32

    -- Key
    local key_buf = buffer(offset, 32)
    tree:add_le(packet.fields.key, key_buf)
    offset = offset + 32

    -- Proof
    -- -----

    -- Field
    local field_buf = buffer(offset, 2)
    local field = field_buf:le_uint()
    tree:add_le(packet.fields.field, field_buf)
    offset = offset + 2

    -- [type]
    local type = field >> 14
    tree:add(packet.fields.type, type) --
    :set_generated(true) --
    :append_text(" (" .. constants.PROOF_NODE_TYPE_BY_VAL[type] .. ")")

    -- Count
    local count_buf = buffer(offset, 2)
    local count = count_buf:le_uint()
    tree:add_le(packet.fields.count, count_buf)
    offset = offset + 2

    -- Prefixes bitfield
    local bsize = count + 7 >> 3
    tree:add_le(packet.fields.prefixes_bitfield, buffer(offset, bsize))
    offset = offset + bsize

    -- Proof nodes
    for i = 0, count - 1, 1 do
        tree:add_le(packet.fields.proofnode, buffer(offset, 32))
        offset = offset + 32
    end

    if type == 1 then
        -- 1 = TYPE_SHORT

        -- Read Prefix
        local prefix_size = buffer(offset, 1):le_uint()
        if (prefix_size & 0x80) ~= 0 then
            -- prefix_size = prefix_size - 0x80
            -- prefix_size = prefix_size * 0x100
            -- prefix_size = prefix_size + buffer(offset, 1):le_uint()
            tree:add_le(packet.fields.prefix_size, buffer(offset, 2))
            offset = offset + 1
        else
            tree:add_le(packet.fields.prefix_size, buffer(offset, 1))
        end
        offset = offset + 1

        tree:add_le(packet.fields.left, buffer(offset, 32))
        offset = offset + 32

        tree:add_le(packet.fields.right, buffer(offset, 32))
        offset = offset + 32

    elseif type == 2 then
        -- 2 = TYPE_COLLISION

        tree:add_le(packet.fields.key, buffer(offset, 32))
        offset = offset + 32
        tree:add_le(packet.fields.value, buffer(offset, 32))
        offset = offset + 32

    elseif type == 3 then
        -- 3 = TYPE_EXISTS

        local size_buf = buffer(offset, 2)
        local size = size_buf:le_uint()
        tree:add_le(packet.fields.size, size_buf)
        offset = offset + 2

        tree:add_le(packet.fields.value, buffer(offset, size))
        offset = offset + size

    end

    -- Info column string
    local info = "root=..." .. root_buf:range(28, 4) .. " key=..." ..
                     key_buf:range(28, 4) .. " type=" .. type

    return offset, info
end

return packet
