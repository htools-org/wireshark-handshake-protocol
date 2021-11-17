utils = {}

function utils.merge_tables(from, to, key_prefix)
    if key_prefix then
        key_prefix = key_prefix .. "_"
    else
        key_prefix = ""
    end
    for k, v in pairs(from) do to[key_prefix .. k] = v end
end

function utils.get_services_list_string(services)
    local res = "["
    if bit32.band(services, 1) ~= 0 then res = res .. " NETWORK" end
    if bit32.band(services, 2) ~= 0 then res = res .. " BLOOM" end
    res = res .. " ]"
    return res
end

function utils.get_varint_value(buffer, offset)
    -- https://github.com/bcoin-org/bufio/blob/91ae6c93899ff9fad7d7cee9afd2a1c4933ca984/lib/encoding.js#L819

    local value, size
    local first_byte = buffer(offset, 1):le_uint()

    if first_byte == 255 then
        size = 9
        value = buffer(offset + 1, 8):le_uint()
    elseif first_byte == 254 then
        size = 5
        value = buffer(offset + 1, 4):le_uint()
    elseif first_byte == 253 then
        size = 3
        value = buffer(offset + 1, 2):le_uint()
    else
        size = 1
        value = first_byte
    end
    return size, value
end

return utils
