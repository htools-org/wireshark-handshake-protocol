-- Headers Packet
local packet = {}

packet.name = "headers"
packet.type = 11

packet.fields = {
    -- Header fields
    nonce = ProtoField.uint32("handshake.block.nonce", "Nonce", base.HEX),
    time = ProtoField.absolute_time("handshake.block.time", "Timestamp",
                                    base.UTC),
    prevblock = ProtoField.bytes("handshake.block.prevblock", "Previous Block",
                                 base.NONE),
    treeroot = ProtoField.bytes("handshake.block.treeroot", "Tree Root",
                                base.NONE),
    extranonce = ProtoField.bytes("handshake.block.extranonce", "Extra Nonce",
                                  base.NONE), -- 24 bytes for nonce
    reservedroot = ProtoField.bytes("handshake.block.reservedroot",
                                    "Reserved Root", base.NONE),
    witnessroot = ProtoField.bytes("handshake.block.witnessroot",
                                   "Witness Root", base.NONE),
    merkleroot = ProtoField.bytes("handshake.block.merkleroot", "Merkle Root",
                                  base.NONE),
    version = ProtoField.uint32("handshake.block.version", "Version", base.DEC),
    bits = ProtoField.uint32("handshake.block.bits", "Bits", base.DEC),
    mask = ProtoField.bytes("handshake.block.mask", "Mask", base.NONE),

    -- Fields for this packet
    headers_count = ProtoField.uint64("handshake.block.headerscount",
                                      "Headers Count", base.DEC)
}

function packet.parse_header(protocol, tree, buffer, offset)
    tree:add_le(packet.fields.nonce, buffer(offset, 4))
    offset = offset + 4

    tree:add_le(packet.fields.time, buffer(offset, 8))
    offset = offset + 8

    tree:add_le(packet.fields.prevblock, buffer(offset, 32))
    offset = offset + 32

    tree:add_le(packet.fields.treeroot, buffer(offset, 32))
    offset = offset + 32

    tree:add_le(packet.fields.extranonce, buffer(offset, 24))
    offset = offset + 24

    tree:add_le(packet.fields.reservedroot, buffer(offset, 32))
    offset = offset + 32

    tree:add_le(packet.fields.witnessroot, buffer(offset, 32))
    offset = offset + 32

    tree:add_le(packet.fields.merkleroot, buffer(offset, 32))
    offset = offset + 32

    tree:add_le(packet.fields.version, buffer(offset, 4))
    offset = offset + 4

    tree:add_le(packet.fields.bits, buffer(offset, 4))
    offset = offset + 4

    tree:add_le(packet.fields.mask, buffer(offset, 32))
    offset = offset + 32

    return offset
end

function packet.parse(protocol, tree, buffer, offset)
    -- Header count
    local count_size, count_value = utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.headers_count, buffer(offset, count_size))
    offset = offset + count_size

    -- Loop for every header
    for i = 0, count_value - 1, 1 do
        local hSubtree = tree:add(protocol,
                                  buffer(offset, constants.BLOCK_HEADER_LEN),
                                  "Header " .. i + 1)

        offset = packet.parse_header(protocol, hSubtree, buffer, offset)
    end

    -- Info column string
    local info = "headers=" .. count_value

    return offset, info
end

return packet
