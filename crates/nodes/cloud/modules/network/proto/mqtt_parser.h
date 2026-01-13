#ifndef MQTT_PARSER_H
#define MQTT_PARSER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// MQTT Control Packet Types
#define MQTT_CONNECT     0x10
#define MQTT_CONNACK     0x20
#define MQTT_PUBLISH     0x30
#define MQTT_PUBACK      0x40
#define MQTT_SUBSCRIBE   0x80
#define MQTT_PINGREQ     0xC0
#define MQTT_PINGRESP    0xD0

// Protocol Constants
#define MQTT_MAX_TOPIC_LEN 256
#define MQTT_MAX_PAYLOAD_LEN 4096

// Simplified Packet Structure
typedef struct {
    uint8_t type;
    uint8_t qos;
    uint16_t packet_id; // For QoS > 0
    char topic[MQTT_MAX_TOPIC_LEN];
    uint16_t topic_len;
    uint8_t *payload;
    size_t payload_len;
} MqttPacket;

/**
 * Parses a raw byte buffer into an MqttPacket struct.
 * Targeted for PUBLISH packets mainly (Data Channels).
 * 
 * @param buffer Raw input buffer
 * @param len Length of buffer
 * @param packet Output struct
 * @return true on success, false on malformed packet
 */
bool mqtt_parse_publish(const uint8_t *buffer, size_t len, MqttPacket *packet);

/**
 * Validates if the topic matches our "Authenticated" topic.
 * Acts as a lightweight Pre-shared Key check.
 * 
 * @param packet Parsed packet
 * @param expected_topic The secret topic string
 * @return true if matches
 */
bool mqtt_validate_topic(const MqttPacket *packet, const char *expected_topic);

#endif // MQTT_PARSER_H
