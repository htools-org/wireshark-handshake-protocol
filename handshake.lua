constants = require("handshake.constants")
utils = require("handshake.utils")
pdu_header = require("handshake.pdu_header")

handshake_protocol = Proto("Handshake", "Handshake Protocol")

-- These packets are loaded from "packet_<type>.lua"
local PACKET_TYPES = {
    "version", "verack", "verack", "ping", "pong", "getaddr", "addr", "inv",
    "getdata", "notfound", "getblocks", "getheaders", "headers", "sendheaders",
    "block", "tx", "reject", "mempool", "filterload", "filteradd",
    "filterclear", "merkleblock", "feefilter", "sendcmpct", "getblocktxn",
    "blocktxn", "getproof", "proof", "claim", "airdrop", "unknown"
}

local packets = {}
payload_parsers = {}
for _, packet_type in pairs(PACKET_TYPES) do
    local packet = require("handshake.packet_" .. packet_type)
    packets[packet_type] = packet
    payload_parsers[packet.type] = packet.parse
end

-- Fields are merged into this table from every packet
handshake_protocol.fields = {}

-- Header fields
utils.merge_tables(pdu_header.fields, handshake_protocol.fields, "packet_header")

-- Payload fields
for _, packet in pairs(packets) do
    utils.merge_tables(packet.fields, handshake_protocol.fields, packet.name)
end

function dissect(buffer, pinfo, tree)

    -- Skip if buffer is empty for some reason.
    local length = buffer:len()
    if length == 0 then return end

    -- Set the Protocol column value
    pinfo.cols.protocol = handshake_protocol.name

    -- Buffer offset
    local offset = 0

    -- Create a Handshake tree and 2 subtrees for header and payload
    local subtree = tree:add(handshake_protocol, buffer(),
                             "Handshake Protocol Data")
    local headerSubtree = subtree:add(handshake_protocol, buffer(offset, 9),
                                      "Header")
    local payloadSubtree = subtree:add(handshake_protocol, buffer(offset + 9),
                                       "Payload")

    -- Header
    offset, type, payload_len = pdu_header.parse(protocol, headerSubtree,
                                                 buffer, offset)
    payloadSubtree.len = payload_len

    -- offset should be 9 at this point (PACKET_HEADER_LEN)

    pinfo.cols.info = "[" .. constants.PAYLOAD_TYPE_BY_VAL[type] .. "] "

    -- Parse payload based on type
    if payload_parsers[type] ~= nil then
        local offset, info = payload_parsers[type](handshake_protocol,
                                                   payloadSubtree, buffer,
                                                   offset)

        -- Append text to Info column
        if info then pinfo.cols.info:append(info) end
    end

    -- Return bytes consumed
    return buffer:len()
end

-- Retruns size of the PDU (header size + payload length)
-- See note for dissect_tcp_pdus.
function get_msg_length(buffer, pinfo, offset)
    local payload_len = buffer(offset + 5, 4):le_uint()
    return constants.PACKET_HEADER_LEN + payload_len
end

-- Called for every TCP packet
function handshake_protocol.dissector(buffer, pinfo, tree)

    -- dissect_tcp_pdus handles desegmentation (when a PDU spans multiple TCP packets)
    -- and also when a TCP packet contains multiple PDUs.
    --
    -- Once PACKET_HEADER_LEN bytes are read, `get_msg_length` is called
    -- to find out the PDU's length (including PDU header).
    -- Then it collects enough TCP packets so that the complete PDU can be
    -- passed to the `dissect` function.
    dissect_tcp_pdus(buffer, tree, constants.PACKET_HEADER_LEN, get_msg_length,
                     dissect, true)
end

-- Register dissector for 4 network ports
local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(12038, handshake_protocol)
tcp_port:add(13038, handshake_protocol)
tcp_port:add(14038, handshake_protocol)
tcp_port:add(15038, handshake_protocol)
