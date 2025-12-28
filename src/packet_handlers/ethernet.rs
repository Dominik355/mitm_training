use anyhow::{Context, Ok, Result};
use pnet::packet::ethernet::{EthernetPacket, MutableEthernetPacket};
use pnet::util::MacAddr;

use crate::packet_handlers::arp::ArpHandler;
use crate::packet_handlers::ipv4::Ipv4Handler;
use pnet::packet::Packet;
use pnet::packet::ethernet::EtherTypes;

pub struct EthernetHandler {
    arp: ArpHandler,
    ipv4: Ipv4Handler,
    own_mac_address: MacAddr,
}

impl EthernetHandler {
    pub fn new(own_mac_address: MacAddr) -> Self {
        Self {
            arp: ArpHandler::new(own_mac_address),
            ipv4: Ipv4Handler::new(),
            own_mac_address,
        }
    }

    /// Handle a raw ethernet packet.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        // TODO: Exercise 1.1
        // Implement the handling of an Ethernet packet. This should call
        // another handler's `.handle_packet()` function depending on the
        // payload type.
        // Once you have implemented the logic for handling any Ethernet packet,
        // move on to ArpHandler to perform the ARP spoofing.
        let eth_packet = EthernetPacket::new(packet).context("Invalid ethernet packet")?;

        if !self.should_intercept(&eth_packet.get_destination()) {
            return Ok(None);
        }

        let inner_payload: Option<Vec<u8>> = match eth_packet.get_ethertype() {
            EtherTypes::Arp => self.arp.handle_packet(eth_packet.payload(), ())?,
            EtherTypes::Ipv4 => self.ipv4.handle_packet(eth_packet.payload(), ())?,
            _ => None,
        };

        if let Some(inner_payload) = inner_payload {
            let mut eth_data =
                vec![0u8; EthernetPacket::minimum_packet_size() + inner_payload.len()];
            let mut eth_pkt =
                MutableEthernetPacket::new(&mut eth_data).expect("cannot build ethernet packet");
            eth_pkt.set_source(self.own_mac_address);
            eth_pkt.set_destination(eth_packet.get_source());
            eth_pkt.set_ethertype(eth_packet.get_ethertype());
            eth_pkt.set_payload(&inner_payload);

            return Ok(Some(eth_data));
        }

        Ok(None)
    }

    fn should_intercept(&self, destination_mac_addr: &MacAddr) -> bool {
        [self.own_mac_address, MacAddr::broadcast(), MacAddr::zero()].contains(destination_mac_addr)
    }
}
