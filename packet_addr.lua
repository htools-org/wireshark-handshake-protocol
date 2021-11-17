local utils = require("handshake.utils")

-- Addr Packet
local packet = {}

packet.name = "addr"
packet.type = 5

packet.fields = {
    -- NetworkAddress fields
    time = ProtoField.absolute_time("handshake.addr.time", "Timestamp", base.UTC),
    services = ProtoField.uint32("handshake.addr.services", "Services", base.DEC),
    raw = ProtoField.ipv6("handshake.addr.raw",
                          "IPv6 (or embedded IPv4) Address", base.NONE),
    port = ProtoField.uint16("handshake.addr.port", "Port", base.DEC),
    key = ProtoField.bytes("handshake.addr.key", "Key", base.NONE),

    -- Fields for this packet
    addr_count = ProtoField.uint64("handshake.addr.count",
                                   "Network Address Count", base.DEC)
}

function packet.parse_network_address(protocol, tree, buffer, offset)
    -- Time
    tree:add_le(packet.fields.time, buffer(offset, 8))
    offset = offset + 8

    -- Services
    local services_buf = buffer(offset, 4)
    tree:add_le(packet.fields.services, services_buf) --
    :append_text(" " .. utils.get_services_list_string(services_buf:le_uint()))
    offset = offset + 4

    -- 5 bytes of unused zeros
    offset = offset + 5

    -- Raw (IPv4, IPv6, Onion address)
    tree:add_le(packet.fields.raw, buffer(offset, 16))
    offset = offset + 16

    -- 20 bytes reserved zeros
    offset = offset + 20

    -- Port
    tree:add_le(packet.fields.port, buffer(offset, 2))
    offset = offset + 2

    -- Key
    tree:add_le(packet.fields.key, buffer(offset, 33))
    offset = offset + 33

    return offset
end

function packet.parse(protocol, tree, buffer, offset)
    -- Get number of addresses
    local addr_count_size, addr_count_value =
        utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.addr_count, buffer(offset, addr_count_size))
    offset = offset + addr_count_size

    -- Loop for every address
    for i = 0, addr_count_value - 1, 1 do
        local naSubtree = tree:add(protocol, buffer(offset, 88),
                                   "NetAddress " .. i + 1)

        offset = packet.parse_network_address(protocol, naSubtree, buffer,
                                              offset)
    end

    -- Info column string
    local info = "addresses=" .. addr_count_value

    return offset, info
end

return packet
