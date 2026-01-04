use std::net::Ipv4Addr;

// Helpers for serializing u16/u32 in Network Byte Order (Big Endian)
fn push_u16(vec: &mut Vec<u8>, val: u16) {
    vec.push((val >> 8) as u8);
    vec.push((val & 0xFF) as u8);
}

fn push_u32(vec: &mut Vec<u8>, val: u32) {
    vec.push((val >> 24) as u8);
    vec.push(((val >> 16) & 0xFF) as u8);
    vec.push(((val >> 8) & 0xFF) as u8);
    vec.push((val & 0xFF) as u8);
}

pub struct Ipv4Header {
    pub src: Ipv4Addr,
    pub dst: Ipv4Addr,
    pub protocol: u8,
    pub id: u16,
    pub ttl: u8,
}

impl Ipv4Header {
    pub fn to_bytes(&self, total_len: u16) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        
        // Ver=4, IHL=5 (20 bytes) => 0x45
        bytes.push(0x45);
        // TOS
        bytes.push(0);
        // Total Length
        push_u16(&mut bytes, total_len);
        // ID
        push_u16(&mut bytes, self.id);
        // Flags (0) + frag off (0)
        push_u16(&mut bytes, 0);
        // TTL
        bytes.push(self.ttl);
        // Protocol
        bytes.push(self.protocol);
        // Checksum (zero first)
        push_u16(&mut bytes, 0);
        // Source
        bytes.extend_from_slice(&self.src.octets());
        // Dest
        bytes.extend_from_slice(&self.dst.octets());
        
        // Calculate IP Checksum
        let checksum = calc_checksum(&bytes);
        bytes[10] = (checksum >> 8) as u8;
        bytes[11] = (checksum & 0xFF) as u8;
        
        bytes
    }
}

pub struct TcpHeader {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
    pub ack: u32,
    pub syn: bool,
    pub ack_flag: bool,
    pub psh: bool,
    pub rst: bool,
    pub fin: bool,
    pub win: u16,
}

impl TcpHeader {
    pub fn to_bytes(&self, src_ip: Ipv4Addr, dst_ip: Ipv4Addr) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(20);
        
        push_u16(&mut bytes, self.src_port);
        push_u16(&mut bytes, self.dst_port);
        push_u32(&mut bytes, self.seq);
        push_u32(&mut bytes, self.ack);
        
        // Data Offset (5) + Reserved (0) + Flags
        // Header Len = 5 * 4 = 20 bytes -> High nibble = 5
        let data_offset = 5 << 4;
        let mut flags = 0u8;
        if self.fin { flags |= 0x01; }
        if self.syn { flags |= 0x02; }
        if self.rst { flags |= 0x04; }
        if self.psh { flags |= 0x08; }
        if self.ack_flag { flags |= 0x10; }
        
        // 16 bits: Offset(4) Res(3) NS(1) | CWR ECE URG ACK PSH RST SYN FIN
        // Simplified: (Offset << 12) | Flags
        // Split into 2 bytes:
        // Byte 12: Data Offset (4 bits) + Res(3) + NS(1)
        // Byte 13: CWR ECE URG ACK PSH RST SYN FIN
        
        // Wait, standard packing:
        // Offset is top 4 bits of byte 12.
        bytes.push(data_offset); // Lower 4 bits are 0 (Res/NS)
        bytes.push(flags);
        
        push_u16(&mut bytes, self.win);
        // Checksum (zero first)
        push_u16(&mut bytes, 0);
        // Urgent Pointer
        push_u16(&mut bytes, 0);
        
        // Calculate TCP Checksum (requires Pseudo Header)
        let checksum = calc_tcp_checksum(&bytes, src_ip, dst_ip, bytes.len() as u16);
        bytes[16] = (checksum >> 8) as u8;
        bytes[17] = (checksum & 0xFF) as u8;
        
        bytes
    }
}

fn calc_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..data.len()).step_by(2) {
        if i + 1 < data.len() {
            let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
            sum = sum.wrapping_add(word);
        } else {
            // Odd byte
            let word = (data[i] as u32) << 8;
            sum = sum.wrapping_add(word);
        }
    }
    
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    
    !sum as u16
}

fn calc_tcp_checksum(tcp_header: &[u8], src: Ipv4Addr, dst: Ipv4Addr, len: u16) -> u16 {
    // Pseudo Header constructed directly below.
    // Hard to partial sum. Let's just build the buffer.
    
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6); // TCP Protocol
    push_u16(&mut pseudo, len);
    pseudo.extend_from_slice(tcp_header);
    
    calc_checksum(&pseudo)
}
