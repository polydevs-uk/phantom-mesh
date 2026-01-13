#include "mqtt_parser.h"
#include <string.h>

// Decode Variable Byte Integer (MQTT Spec 2.2.3)
// Returns value and updates *bytes_read
static uint32_t decode_var_length(const uint8_t *buffer, size_t max_len, size_t *bytes_read) {
    uint32_t value = 0;
    uint32_t multiplier = 1;
    size_t len = 0;
    uint8_t byte;

    do {
        if (len >= max_len) return 0; // Overflow protection
        byte = buffer[len];
        value += (byte & 127) * multiplier;
        multiplier *= 128;
        len++;
    } while ((byte & 128) != 0);

    *bytes_read = len;
    return value;
}

bool mqtt_parse_publish(const uint8_t *buffer, size_t len, MqttPacket *packet) {
    if (len < 2) return false;

    // 1. Fixed Header (Byte 1)
    // PUBLISH = 0x3n (where n is flags)
    // Mask out flags (0xF0) to check type 0x30
    if ((buffer[0] & 0xF0) != MQTT_PUBLISH) {
        return false;
    }
    
    packet->type = MQTT_PUBLISH;
    packet->qos = (buffer[0] >> 1) & 0x03; // Bit 1-2

    size_t offset = 1;

    // 2. Remaining Length (Variable Header)
    size_t var_len_bytes = 0;
    uint32_t remaining_len = decode_var_length(buffer + offset, len - offset, &var_len_bytes);
    offset += var_len_bytes;

    if (offset + remaining_len > len) return false; // Packet incomplete

    // 3. Variable Header: Topic Name (Length MSB+LSB + String)
    if (offset + 2 > len) return false;
    uint16_t topic_len_raw = (buffer[offset] << 8) | buffer[offset+1];
    offset += 2;

    if (topic_len_raw > MQTT_MAX_TOPIC_LEN - 1) return false; // Too long for our buffer
    if (offset + topic_len_raw > len) return false;

    // Copy Topic
    memcpy(packet->topic, buffer + offset, topic_len_raw);
    packet->topic[topic_len_raw] = '\0'; // Null-terminate
    packet->topic_len = topic_len_raw;
    offset += topic_len_raw;

    // 4. Packet Identifier (Only if QoS > 0)
    if (packet->qos > 0) {
        if (offset + 2 > len) return false;
        packet->packet_id = (buffer[offset] << 8) | buffer[offset+1];
        offset += 2;
    } else {
        packet->packet_id = 0;
    }

    // 5. Payload
    // The rest is payload
    packet->payload_len = len - offset;
    if (packet->payload_len > 0) {
        packet->payload = (uint8_t *)(buffer + offset);
    } else {
        packet->payload = NULL;
    }

    return true;
}

bool mqtt_validate_topic(const MqttPacket *packet, const char *expected_topic) {
    if (packet->topic_len == 0) return false;
    return strcmp(packet->topic, expected_topic) == 0;
}
