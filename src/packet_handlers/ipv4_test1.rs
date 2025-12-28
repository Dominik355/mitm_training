// TODO: remove the line below when working on the file
#![expect(unused_variables, dead_code)]

use anyhow::Result;
use log::info;

pub struct Ipv4Test1Handler {}

impl Ipv4Test1Handler {
    pub fn new() -> Self {
        Self {}
    }

    /// Handle a raw packet of IPv4 Test1.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(&mut self, packet: &[u8], _options: ()) -> Result<Option<Vec<u8>>> {
        // TODO: Exercise 2.2
        // Implement the handling of an IPv4 Test1 packet.
        // This service should echo back the received packet.
        // Once correctly implemented, you should pass test case #2.

        info!(
            "Handling Test1 IPV4 [{}]: {:?}",
            packet.len(),
            String::from_utf8_lossy(&packet)
        );

        if !self.should_intercept() {
            return Ok(None);
        }

        Ok(Some(packet.to_vec()))
    }

    fn should_intercept(&self) -> bool {
        // TODO: implement your custom interception logic here. You may pass
        // additional parameters to this function.
        true
    }
}
