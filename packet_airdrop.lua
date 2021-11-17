-- local utils = require("handshake.utils")
-- local AddrPacket = require("handshake.packet_addr")
-- Airdrop Packet
local packet = {}

packet.name = "airdrop"
packet.type = 29

packet.fields = {
    index = ProtoField.uint32("handshake.airdrop.index", "Index (leaf)",
                              base.DEC),
    proof_hash_count = ProtoField.uint8("handshake.airdrop.proof.hash_count",
                                        "Proof Hash Count", base.DEC),
    proof_hash = ProtoField.bytes("handshake.airdrop.proof.hash", "Proof Hash",
                                  base.NONE),
    subindex = ProtoField.uint8("handshake.airdrop.subindex",
                                "Sub-index (leaf)", base.DEC),
    subproof_hash_count = ProtoField.uint8(
        "handshake.airdrop.subproof.hash_count", "Sub-proof Hash Count",
        base.DEC),
    subproof_hash = ProtoField.bytes("handshake.airdrop.subproof.hash",
                                     "Sub-proof Hash", base.NONE),
    key_length = ProtoField.uint64("handshake.airdrop.key.length", "Key Length",
                                   base.DEC),
    key = ProtoField.bytes("handshake.airdrop.key", "Key", base.NONE),
    version = ProtoField.uint8("handshake.airdrop.version", "Version", base.DEC),
    address_length = ProtoField.uint8("handshake.airdrop.address.length",
                                      "Address Length", base.DEC),
    address = ProtoField.bytes("handshake.airdrop.address", "Address", base.NONE),
    fee = ProtoField.uint64("handshake.airdrop.fee", "Fee", base.DEC),
    signature_length = ProtoField.uint64("handshake.airdrop.signature.length",
                                         "Signature Length", base.DEC),
    signature = ProtoField.bytes("handshake.airdrop.signature", "Signature",
                                 base.NONE)
}

function packet.parse(protocol, tree, buffer, offset)
    -- Index
    local index_buf = buffer(offset, 4)
    tree:add_le(packet.fields.index, index_buf)
    offset = offset + 4

    -- Proof hash count
    local proof_hash_count_buf = buffer(offset, 1)
    local proof_hash_count = proof_hash_count_buf:le_uint()
    tree:add_le(packet.fields.proof_hash_count, proof_hash_count_buf)
    offset = offset + 1

    -- Proof hashes
    for i = 0, proof_hash_count - 1, 1 do
        tree:add_le(packet.fields.proof_hash, buffer(offset, 32))
        offset = offset + 32
    end

    -- Subindex
    local subindex_buf = buffer(offset, 1)
    tree:add_le(packet.fields.subindex, subindex_buf)
    offset = offset + 1

    -- Sub-proof hash count
    local subproof_hash_count_buf = buffer(offset, 1)
    local subproof_hash_count = subproof_hash_count_buf:le_uint()
    tree:add_le(packet.fields.subproof_hash_count, subproof_hash_count_buf)
    offset = offset + 1

    -- Sub-proof hashes
    for i = 0, subproof_hash_count - 1, 1 do
        tree:add_le(packet.fields.subproof_hash, buffer(offset, 32))
        offset = offset + 32
    end

    -- Key length
    local keylength_size, keylength_value =
        utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.key_length, buffer(offset, keylength_size)) --
    :append_text(" bytes")
    offset = offset + keylength_size

    -- Key
    tree:add_le(packet.fields.key, buffer(offset, keylength_value))
    offset = offset + keylength_value

    -- Version
    tree:add_le(packet.fields.version, buffer(offset, 1))
    offset = offset + 1

    -- Address length
    local addrlength_size, addrlength_value =
        utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.address_length, buffer(offset, addrlength_size)) --
    :append_text(" bytes")
    offset = offset + addrlength_size

    -- Address
    tree:add_le(packet.fields.address, buffer(offset, addrlength_value))
    offset = offset + addrlength_value

    -- Fee
    local fee_size, fee_value = utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.fee, buffer(offset, fee_size))
    offset = offset + fee_size

    -- Signature length
    local siglength_size, siglength_value =
        utils.get_varint_value(buffer, offset)
    tree:add_le(packet.fields.signature_length, buffer(offset, siglength_size)) --
    :append_text(" bytes")
    offset = offset + siglength_size

    -- Signature
    tree:add_le(packet.fields.signature, buffer(offset, siglength_value))
    offset = offset + siglength_value

    -- Info column string
    local info = "index=" .. index_buf:le_uint() .. " subindex=" ..
                     subindex_buf:le_uint()
    return offset, info
end

return packet
