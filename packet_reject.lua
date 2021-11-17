-- Reject Packet
local packet = {}

packet.name = "reject"
packet.type = 15

packet.fields = {
    message = ProtoField.uint8("handshake.reject.message",
                               "Reject Message (payload)", base.DEC),
    code = ProtoField.uint8("handshake.reject.code", "Reject Code", base.DEC),
    reason_length = ProtoField.uint8("handshake.reject.reason.length",
                                     "Reject Reason Length", base.DEC),
    reason = ProtoField.string("handshake.reject.reason", "Reject Reason",
                               base.ASCII),
    hash = ProtoField.bytes("handshake.reject.hash", "Hash", base.NONE)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Message
    local message_buf = buffer(offset, 1)
    local message = constants.PAYLOAD_TYPE_BY_VAL[message_buf:le_uint()]
    tree:add(packet.fields.message, message_buf) --
    :append_text(" (" .. message .. ")")
    offset = offset + 1

    -- Code
    local code_buf = buffer(offset, 1)
    local code = constants.REJECT_CODE_BY_VAL[code_buf:le_uint()]
    tree:add(packet.fields.code, code_buf) --
    :append_text(" (" .. code .. ")")
    offset = offset + 1

    -- Reason
    local reason_length_buf = buffer(offset, 1)
    local reason_length = reason_length_buf:le_uint()
    tree:add(packet.fields.reason_length, reason_length_buf) --
    :append_text(" bytes")
    offset = offset + 1

    local reason_buf = buffer(offset, reason_length)
    tree:add(packet.fields.reason, reason_buf)
    offset = offset + reason_length

    local msg_num = message_buf:le_uint()

    -- Hash only if message is one of: BLOCK, TX, CLAIM, AIRDROP
    if msg_num == 13 or msg_num == 14 or msg_num == 28 or msg_num == 29 then
        tree:add(packet.fields.hash, buffer(offset, 32))
        offset = offset + 32
    end

    -- Info column string
    local info = "message=" .. message .. " code=" .. code .. " reason=" ..
                     reason_buf:string()

    return offset, info
end

return packet
