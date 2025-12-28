use crate::constants::{SERVER_IP, VICTIM_IP};
use crate::packet_handlers::ipv4_test1::Ipv4Test1Handler;
use crate::packet_handlers::tcp::{TcpHandler, TcpHandlerOptions};
use anyhow::Result;
use log::info;
use pnet::packet::Packet;
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::packet::ip::{IpNextHeaderProtocol, IpNextHeaderProtocols};
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use std::net::Ipv4Addr;

pub struct Ipv4Handler {
    tcp_handler: TcpHandler,
    test1_handler: Ipv4Test1Handler,
    expected_victim_ip: Ipv4Addr,
    expected_asked_ip: Ipv4Addr,
}

impl Ipv4Handler {
    pub fn new() -> Self {
        Self {
            tcp_handler: TcpHandler::new(),
            test1_handler: Ipv4Test1Handler::new(),

            expected_victim_ip: VICTIM_IP.parse().unwrap(),
            expected_asked_ip: SERVER_IP.parse().unwrap(),
        }
    }

    /// Handle a raw IPv4 packet.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        // TODO: Exercise 2.1
        // Implement the handling of an IPv4 packet. This should call another
        // handler's `.handle_packet()` function depending on the payload type.
        // Once you have implemented the logic for handling any IPv4 packet,
        // move on to `IPv4TestHandler` to implement the echo service.

        let ipv4_pkt = Ipv4Packet::new(packet).ok_or(anyhow::Error::msg("Invalid IPv4 packet"))?;

        if !self.should_intercept(ipv4_pkt.get_source(), ipv4_pkt.get_destination()) {
            return Ok(None);
        }

        let inner_payload = match ipv4_pkt.get_next_level_protocol() {
            IpNextHeaderProtocols::Tcp => {
                let tcp_options = TcpHandlerOptions {
                    src_ip: ipv4_pkt.get_source(),
                    dst_ip: ipv4_pkt.get_destination(),
                };
                self.tcp_handler
                    .handle_packet(ipv4_pkt.payload(), &tcp_options)
            }
            IpNextHeaderProtocols::Test1 => {
                self.test1_handler.handle_packet(ipv4_pkt.payload(), ())
            }
            _ => Ok(None),
        }?;

        if let Some(inner_payload) = inner_payload {
            let mut resp_data = vec![0u8; Ipv4Packet::minimum_packet_size() + inner_payload.len()];
            let mut resp =
                MutableIpv4Packet::new(&mut resp_data).expect("cannot build ipv4 packet");

            resp.set_source(ipv4_pkt.get_destination());
            resp.set_destination(ipv4_pkt.get_source());

            resp.set_total_length((Ipv4Packet::minimum_packet_size() + inner_payload.len()) as u16);

            resp.set_next_level_protocol(ipv4_pkt.get_next_level_protocol());
            resp.set_version(ipv4_pkt.get_version());
            resp.set_header_length(ipv4_pkt.get_header_length());
            resp.set_flags(ipv4_pkt.get_flags());
            resp.set_fragment_offset(ipv4_pkt.get_fragment_offset());
            resp.set_ttl(ipv4_pkt.get_ttl());
            resp.set_payload(&inner_payload);

            resp.set_checksum(pnet::packet::ipv4::checksum(&resp.to_immutable()));

            return anyhow::Ok(Some(resp_data));
        }

        Ok(None)
    }

    fn should_intercept(&self, sender_ip: Ipv4Addr, target_ip: Ipv4Addr) -> bool {
        sender_ip == self.expected_victim_ip && target_ip == self.expected_asked_ip
    }
}
