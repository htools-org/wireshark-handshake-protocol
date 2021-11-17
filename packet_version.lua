local utils = require("handshake.utils")

local AddrPacket = require("handshake.packet_addr")

-- Version Packet
local packet = {}

packet.name = "version"
packet.type = 0

packet.fields = {
    version = ProtoField.uint32("handshake.version.version", "Protocol Version",
                                base.DEC),
    services = ProtoField.uint32("handshake.version.services", "Services",
                                 base.DEC),
    timestamp = ProtoField.absolute_time("handshake.version.timestamp",
                                         "Timestamp", base.UTC),
    nonce = ProtoField.uint64("handshake.version.nonce", "Nonce", base.HEX),
    agent_length = ProtoField.uint8("handshake.version.agent.length",
                                    "Agent Length", base.DEC),
    agent = ProtoField.string("handshake.version.agent.value", "Agent",
                              base.ASCII),
    height = ProtoField.uint32("handshake.version.height", "Height", base.DEC),
    norelay = ProtoField.bool("handshake.version.norelay", "No Relay", base.NONE)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Version
    tree:add_le(packet.fields.version, buffer(offset, 4))
    offset = offset + 4

    -- Services
    local services_buf = buffer(offset, 4)
    tree:add_le(packet.fields.services, services_buf) --
    :append_text(" " .. utils.get_services_list_string(services_buf:le_uint()))
    offset = offset + 4

    -- 4 bytes of unused zeros
    offset = offset + 4

    -- Timestamp
    tree:add_le(packet.fields.timestamp, buffer(offset, 8))
    offset = offset + 8

    -- Remote
    local remoteSubtree = tree:add(protocol, buffer(offset, 88), "Remote")
    offset = AddrPacket.parse_network_address(protocol, remoteSubtree, buffer,
                                              offset)

    -- Nonce
    tree:add_le(packet.fields.nonce, buffer(offset, 8))
    offset = offset + 8

    -- Agent
    local agent_length_buf = buffer(offset, 1)
    local agent_length = agent_length_buf:le_uint()
    tree:add_le(packet.fields.agent_length, agent_length_buf) --
    :append_text(" bytes")
    offset = offset + 1
    local agent_buf = buffer(offset, agent_length)
    tree:add_le(packet.fields.agent, agent_buf)
    offset = offset + agent_length

    -- Height
    local height_buf = buffer(offset, 4)
    tree:add_le(packet.fields.height, height_buf)
    offset = offset + 4

    -- NoRelay
    tree:add_le(packet.fields.norelay, buffer(offset, 1))
    offset = offset + 1

    -- Info column string
    local info = "agent=" .. agent_buf:string() .. " height=" ..
                     height_buf:le_uint()
    return offset, info
end

return packet
