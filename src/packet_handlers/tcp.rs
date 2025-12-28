// TODO: remove the line below when working on the file
#![expect(unused_variables, dead_code)]

use alloc::collections;
use std::collections::HashMap;
use std::io::Cursor;
use std::net::Ipv4Addr;

use anyhow::{Result, anyhow, bail};
use log::{LevelFilter, info};
use pnet::packet::Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use rand::Rng;

use crate::models::{AppBuffer, ConnectionId};
use crate::packet_handlers::echo::EchoHandler;
use crate::packet_handlers::http::HttpHandler;
use crate::packet_handlers::tls::TlsHandler;

/// Represent the initial state of a TCP connection
#[derive(Clone, Debug, PartialEq)]
enum TcpState {
    /// A SYN has been received but we are waiting for an ACK
    InitialSynReceived,
    /// 3-way handshake has been completed, data can be exchanged on the connection
    Established,
    /// A side has asked to close the connection, we are waiting for the final ACK.
    Closing,
}

/// Hold the internal TCP connection information like its internal state, the current sequence numbers, the total data sent / received or the internal data buffer.
#[derive(Debug)]
struct TcpConnectionInfo {
    /// Internal TCP state
    pub state: TcpState,
    /// Buffer containing the received data
    pub buffer: AppBuffer,
    /// Current client sequence number
    pub client_seq_number: u32,
    /// Current server sequence number
    pub server_seq_number: u32,
    /// Total received data
    pub total_data_rx: usize,
    /// Total sent data
    pub total_data_tx: usize,
}

impl TcpConnectionInfo {
    pub fn new(client_seq_number: u32) -> Self {
        let mut rng = rand::rng();
        Self {
            state: TcpState::InitialSynReceived,
            server_seq_number: rng.random::<u32>(),
            client_seq_number,
            buffer: AppBuffer::new(client_seq_number + 1),
            total_data_rx: 0,
            total_data_tx: 0,
        }
    }
}

fn is_tcp_flag_set(flags: u8, expected_flag: u8) -> bool {
    flags & expected_flag == expected_flag
}

fn craft_tcp_packet(
    connection_id: &ConnectionId,
    seq: u32,
    ack: u32,
    flags: u8,
    data: Option<Vec<u8>>,
) -> Result<Vec<u8>> {
    // TODO: Exercise 3.0
    // Implement the crafting of a valid TCP packet with the given parameters.
    // Make sure the TCP checksum for the packet is correct.
    let mut tcp_data = vec![
        0u8;
        TcpPacket::minimum_packet_size()
            + data.as_ref().map(|d| d.len()).unwrap_or_default()
    ];
    let mut tcp_pkt = MutableTcpPacket::new(&mut tcp_data).expect("cannot build tcp packet");

    tcp_pkt.set_source(connection_id.dst_port());
    tcp_pkt.set_destination(connection_id.src_port());
    tcp_pkt.set_sequence(seq);
    tcp_pkt.set_acknowledgement(ack);
    tcp_pkt.set_flags(flags);
    tcp_pkt.set_data_offset(20 / 4);
    tcp_pkt.set_window(u16::MAX);
    if let Some(data) = data {
        tcp_pkt.set_payload(data.as_ref());
    }

    tcp_pkt.set_checksum(pnet::packet::tcp::ipv4_checksum(
        &tcp_pkt.to_immutable(),
        &connection_id.dst_ip(),
        &connection_id.src_ip(),
    ));

    info!("Replying TCP packet: \n{:#?}", tcp_pkt);

    Ok(tcp_data)
}

pub struct TcpHandler {
    // K = (ip_src, port_src, ip_dst, port_dst) / V = Actual connection information
    active_connections: HashMap<ConnectionId, TcpConnectionInfo>,
    http: HttpHandler,
    tls: TlsHandler,
    echo: EchoHandler,
}

impl TcpHandler {
    pub fn new() -> Self {
        Self {
            active_connections: HashMap::new(),
            http: HttpHandler::new(),
            tls: TlsHandler::new(),
            echo: EchoHandler::new(),
        }
    }

    /// Handle a raw TCP packet.
    ///
    /// ## Returns
    ///
    /// - Ok(Vec<u8>) to send a reponse
    /// - Ok(None) to ignore the packet
    /// - Err on error
    pub fn handle_packet(
        &mut self,
        packet: &[u8],
        options: &TcpHandlerOptions,
    ) -> Result<Option<Vec<u8>>> {
        log::trace!("received TCP packet...");

        let Some(inbound_tcp_packet) = TcpPacket::new(packet) else {
            bail!("cannot create tcp packet...")
        };

        info!("Received TCP packet : {:#?}", inbound_tcp_packet);

        let src_ip = options.src_ip;
        let dst_ip = options.dst_ip;

        let dst_port = inbound_tcp_packet.get_destination();
        let src_port = inbound_tcp_packet.get_source();
        let flags = inbound_tcp_packet.get_flags();
        let seq = inbound_tcp_packet.get_sequence();
        let data = inbound_tcp_packet.payload();

        if !self.should_intercept() {
            return Ok(None);
        }

        log::debug!("Found target to intercept: {dst_ip}:{dst_port}");

        let syn_flag_set = is_tcp_flag_set(flags, TcpFlags::SYN);
        let ack_flag_set = is_tcp_flag_set(flags, TcpFlags::ACK);
        let psh_flag_set = is_tcp_flag_set(flags, TcpFlags::PSH);
        let fin_flag_set = is_tcp_flag_set(flags, TcpFlags::FIN);
        let rst_flag_set = is_tcp_flag_set(flags, TcpFlags::RST);

        if log::log_enabled!(log::Level::Trace) && log::max_level() == LevelFilter::Trace {
            let flags = [
                (syn_flag_set, "SYN"),
                (ack_flag_set, "ACK"),
                (psh_flag_set, "PSH"),
                (fin_flag_set, "FIN"),
                (rst_flag_set, "RST"),
            ];

            let flags_str = flags
                .iter()
                .filter_map(|(set, name)| if *set { Some(*name) } else { None })
                .collect::<Vec<_>>()
                .join("|");

            log::trace!("TCP flags: |{flags_str}|");
        }

        let connection_id = ConnectionId::new(src_ip, src_port, dst_ip, dst_port);

        if rst_flag_set {
            log::trace!("received RST from {src_ip}:{src_port}");
            return self.handle_tcp_rst(&connection_id);
        }

        if fin_flag_set {
            log::trace!("received FIN from {src_ip}:{src_port}");
            return self.handle_tcp_fin(
                &connection_id,
                seq,
                inbound_tcp_packet.get_acknowledgement(),
            );
        }

        if syn_flag_set {
            log::trace!("[+] SYN from {src_ip}:{src_port}");
            log::trace!(
                "-> SYN -> SEQ: {} - ACK {}",
                seq,
                inbound_tcp_packet.get_acknowledgement()
            );

            return self.handle_tcp_syn(&connection_id, seq);
        }

        if ack_flag_set {
            log::trace!(
                "RECV -> ACK | SEQ: {} - ACK {} - data_len={}",
                inbound_tcp_packet.get_sequence(),
                inbound_tcp_packet.get_acknowledgement(),
                data.len()
            );
            self.handle_tcp_ack(&connection_id, inbound_tcp_packet.get_acknowledgement())?;
        }

        // data is sometimes sent without a PSH...
        if psh_flag_set || !data.is_empty() {
            log::trace!("[DATA] SEQ={} | LEN={}", seq, data.len());
            return self.handle_tcp_psh(&connection_id, seq, data);
        }

        Ok(None)
    }

    fn should_intercept(&self) -> bool {
        // TODO: implement your custom interception logic here. You may pass
        // additional parameters to this function.
        true
    }

    fn handle_tcp_syn(
        &mut self,
        connection_id: &ConnectionId,
        seq_number: u32,
    ) -> Result<Option<Vec<u8>>> {
        let conn = TcpConnectionInfo::new(seq_number);
        let server_initial_seq = conn.server_seq_number;

        self.active_connections
            .insert(connection_id.to_owned(), conn);

        // Send SYN-ACK
        Ok(Some(craft_tcp_packet(
            connection_id,
            server_initial_seq,
            seq_number + 1,
            TcpFlags::SYN | TcpFlags::ACK,
            None,
        )?))
    }

    fn handle_tcp_ack(&mut self, connection_id: &ConnectionId, ack: u32) -> Result<()> {
        // TODO: Exercise 3.2
        // Implement the handling of a packet containing a TCP ACK flag. This
        // function can be called alongside `handle_tcp_psh`.

        let mut connection = self
            .active_connections
            .get_mut(connection_id)
            .ok_or(anyhow!(
                "Obtained ACK for non existing connection:  {connection_id:?}"
            ))?;

        match connection.state {
            TcpState::InitialSynReceived => {
                if ack != connection.server_seq_number + 1 {
                    bail!(
                        "ACK mismatch! Expected {}, got {}",
                        connection.server_seq_number,
                        ack
                    )
                }

                log::info!(
                    "opened tcp connection with {}:{}",
                    connection_id.src_ip(),
                    connection_id.src_port()
                );

                connection.state = TcpState::Established;
                connection.server_seq_number = ack;
            }
            TcpState::Established => {}
            TcpState::Closing => {
                let conn = self.active_connections.remove(connection_id);
                let (total_amount_rx, total_amount_tx) = conn
                    .map(|c| (c.total_data_rx, c.total_data_tx))
                    .unwrap_or_default();

                info!(
                    "closed connection with {}:{}. rx_data={total_amount_rx} tx_data={total_amount_tx}",
                    connection_id.src_ip(),
                    connection_id.src_port()
                );
            }
        }

        Ok(())
    }

    fn handle_tcp_psh(
        &mut self,
        connection_id: &ConnectionId,
        seq_number: u32,
        data: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        // TODO: Exercise 3.3
        // Implement the handling of a packet containing a TCP PSH flag. You
        // should use `TcpConnectionInfo.buffer` to store the received payload.
        // This should call another handler's `.handle_packet()` function
        // depending on the payload type.
        // Once you have implemented the logic for handling any TCP packet,
        // the payload type.

        let mut connection = self
            .active_connections
            .get_mut(connection_id)
            .ok_or(anyhow!(
                "Obtained PSH before SYN for connection {connection_id:?}"
            ))?;

        let data_len = data.len();

        connection.total_data_rx += data_len;

        if seq_number != connection.client_seq_number + 1 {
            bail!(
                "Was expecting {} seq number but received {}",
                connection.server_seq_number + 1,
                seq_number
            );
        }

        let mut buffer = AppBuffer::new(seq_number);
        buffer.insert(seq_number, data);
        let data = self.echo.handle_packet(&mut buffer, ())?;

        data.as_ref()
            .inspect(|d| connection.total_data_tx += d.len());

        craft_tcp_packet(
            connection_id,
            connection.server_seq_number + 1,
            connection.client_seq_number + 1 + data_len as u32,
            TcpFlags::PSH | TcpFlags::ACK,
            data,
        )
        .map(Some)
    }

    fn handle_tcp_fin(
        &mut self,
        connection_id: &ConnectionId,
        seq_number: u32,
        ack_number: u32,
    ) -> Result<Option<Vec<u8>>> {
        // TODO: Exercise 3.5
        // Implement the handling of a packet containing a TCP FIN flag. This
        // function performs an early return in our TCP state machine, so no
        // other handler will be called even if the incoming packet contains
        // additional flags.
        // Once correctly implemented, you should pass test case #3.

        let mut connection = self
            .active_connections
            .get_mut(connection_id)
            .ok_or(anyhow!(
                "Obtained FIN for not existing connection {connection_id:?}"
            ))?;

        connection.state = TcpState::Closing;

        craft_tcp_packet(
            connection_id,
            ack_number,
            seq_number + 1,
            TcpFlags::ACK | TcpFlags::FIN,
            None,
        )
        .map(Some)
    }

    fn handle_tcp_rst(&mut self, connection_id: &ConnectionId) -> Result<Option<Vec<u8>>> {
        self.active_connections.remove(connection_id);
        Ok(None)
    }
}

pub struct TcpHandlerOptions {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
}
