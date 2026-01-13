#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "mqtt_parser.h"

void test_valid_publish() {
    printf("[Test] Valid PUBLISH Packet...\n");
    
    // Construct a simpler known packet
    // Type: PUBLISH (0x30) | QoS 0
    // Topic: "test" (len 4)
    // Payload: "HELLO" (len 5)
    
    // Header 0x30
    // Remaining Length: 2 (topic len) + 4 (topic "test") + 5 (payload) = 11 (0x0B)
    
    uint8_t packet[] = {
        0x30, 0x0B,             // Header + Length
        0x00, 0x04,             // Topic Len (4)
        't', 'e', 's', 't',     // Topic
        'H', 'E', 'L', 'L', 'O' // Payload
    };
    
    MqttPacket parsed;
    bool result = mqtt_parse_publish(packet, sizeof(packet), &parsed);
    
    assert(result == true);
    assert(strcmp(parsed.topic, "test") == 0);
    assert(parsed.qos == 0);
    assert(parsed.payload_len == 5);
    assert(memcmp(parsed.payload, "HELLO", 5) == 0);
    
    printf("PASS\n");
}

void test_invalid_header() {
    printf("[Test] Invalid Header...\n");
    uint8_t packet[] = { 0x10, 0x00 }; // CONNECT packet
    MqttPacket parsed;
    bool result = mqtt_parse_publish(packet, sizeof(packet), &parsed);
    assert(result == false);
    printf("PASS\n");
}

int main() {
    test_valid_publish();
    test_invalid_header();
    printf("All Tests Passed.\n");
    return 0;
}
