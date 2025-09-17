use std::{
    io::{Read, Write},
    os::fd::{AsRawFd, IntoRawFd, RawFd},
};

use std::io::{Error, ErrorKind, Result};

use crate::tun::fd::Fd;

#[derive(Debug)]
pub struct Tun {
    fd: Fd,
    buf: Vec<u8>,
    mtu: u16,
    pub packet_info: bool,
}

impl Tun {
    pub fn new(fd: Fd, mtu: u16, packet_info: bool) -> Self {
        let offset = if packet_info { 4 } else { 0 };
        let buf_size = mtu as usize + offset;

        Self {
            fd,
            buf: vec![0; buf_size],
            mtu,
            packet_info,
        }
    }

    pub fn offset(&self) -> usize {
        if self.packet_info {
            4
        } else {
            0
        }
    }

    pub fn generate_packet_header(&self, ipv6: bool) -> Option<[u8; 4]> {
        #[cfg(target_os = "linux")]
        const TUN_IPV6_HEADER: [u8; 4] = ((libc::ETH_P_IPV6) as u32).to_be_bytes();
        #[cfg(target_os = "linux")]
        const TUN_IPV4_HEADER: [u8; 4] = ((libc::ETH_P_IP) as u32).to_be_bytes();

        #[cfg(target_os = "macos")]
        const TUN_IPV6_HEADER: [u8; 4] = ((libc::AF_INET6) as u32).to_be_bytes();
        #[cfg(target_os = "macos")]
        const TUN_IPV4_HEADER: [u8; 4] = ((libc::AF_INET) as u32).to_be_bytes();

        if !self.packet_info {
            return None;
        }

        if ipv6 {
            Some(TUN_IPV6_HEADER)
        } else {
            Some(TUN_IPV4_HEADER)
        }
    }

    pub fn set_nonblocking(&self) -> Result<()> {
        self.fd.set_nonblocking()
    }

    pub fn set_mtu(&mut self, value: u16) {
        self.mtu = value;
        let new_size = value as usize + self.offset();
        if new_size > self.buf.len() {
            self.buf.resize(new_size, 0);
        }
    }
}

pub fn is_ipv6(buf: &[u8]) -> Result<bool> {
    if buf.is_empty() {
        return Err(Error::new(ErrorKind::InvalidData, "Zero length buffer"));
    }

    match buf[0] >> 4 {
        4 => Ok(false),
        6 => Ok(true),
        p => Err(Error::new(
            ErrorKind::InvalidData,
            format!("IP version {p}"),
        )),
    }
}

impl Read for Tun {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if !self.packet_info {
            return self.fd.read(buf);
        }

        let offset = self.offset();

        let max_read_size = self.mtu as usize + offset;
        let requested_size = buf.len() + offset;
        let actual_read_size = requested_size.min(max_read_size);

        if actual_read_size > self.buf.len() {
            self.buf.resize(actual_read_size, 0);
        }

        let amount = self.fd.read(&mut self.buf[..actual_read_size])?;
        if amount <= offset {
            return Ok(0);
        }

        let to_copy = buf.len().min(amount.saturating_sub(offset));
        buf[..to_copy].copy_from_slice(&self.buf[offset..offset + to_copy]);
        Ok(to_copy)
    }
}

impl Write for Tun {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        if !self.packet_info {
            return self.fd.write(buf);
        }

        let offset = self.offset();

        let buf_len = buf.len() + offset;
        if buf_len > self.buf.len() {
            self.buf.resize(buf_len, 0);
        }

        let is_ipv6 = is_ipv6(buf)?;
        let header = self.generate_packet_header(is_ipv6).ok_or_else(|| {
            Error::new(ErrorKind::InvalidData, "Failed to generate packet header")
        })?;

        self.buf[..offset].copy_from_slice(&header);
        self.buf[offset..buf_len].copy_from_slice(buf);

        let amount = self.fd.write(&self.buf[..buf_len])?;
        if amount <= offset {
            return Ok(0);
        }

        Ok(amount - offset)
    }

    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}

impl AsRawFd for Tun {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

impl IntoRawFd for Tun {
    fn into_raw_fd(self) -> RawFd {
        self.fd.into_raw_fd()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_fds() -> [i32; 2] {
        let mut fds = [0; 2];
        unsafe { libc::pipe(fds.as_mut_ptr()) };

        return fds;
    }

    #[test]
    fn test_tun_new_without_packet_info() {
        let [fd_1, _] = setup_fds();

        let fd = Fd::new(fd_1, true).unwrap();

        let tun = Tun::new(fd, 1500, false);

        assert_eq!(tun.offset(), 0);
        assert_eq!(tun.buf.len(), 1500);
        assert!(!tun.packet_info);
    }

    #[test]
    fn test_tun_new_with_packet_info() {
        let [fd_1, _] = setup_fds();

        let fd = Fd::new(fd_1, true).unwrap();

        let tun = Tun::new(fd, 1500, true);

        assert_eq!(tun.offset(), 4);
        assert_eq!(tun.buf.len(), 1500 + 4);
        assert!(tun.packet_info);
    }

    #[test]
    fn test_generate_packet_header() {
        let [fd_1, _] = setup_fds();

        let fd = Fd::new(fd_1, true).unwrap();

        let tun = Tun::new(fd, 1500, true);

        assert_eq!(
            tun.generate_packet_header(false).unwrap(),
            (libc::AF_INET as u32).to_be_bytes()
        );
        assert_eq!(
            tun.generate_packet_header(true).unwrap(),
            (libc::AF_INET6 as u32).to_be_bytes()
        )
    }

    #[test]
    fn test_read_write_no_packet_info() {
        let [fd_1, fd_2] = setup_fds();

        let reader = Fd::new(fd_1, true).unwrap();
        let writer = Fd::new(fd_2, true).unwrap();

        let mut tun_reader = Tun::new(reader, 1500, false);
        let mut tun_writer = Tun::new(writer, 1500, false);

        let msg = b"hello";
        tun_writer.write(msg).unwrap();

        let mut buf = [0u8; 5];
        let len = tun_reader.read(&mut buf).unwrap();

        assert_eq!(&buf[..len], msg);
        assert_eq!(len, msg.len());
    }

    #[test]
    fn test_send_recv_with_packet_info_ipv4() {
        let [fd_1, fd_2] = setup_fds();

        let reader = Fd::new(fd_1, true).unwrap();
        let writer = Fd::new(fd_2, true).unwrap();

        let mut tun_reader = Tun::new(reader, 1500, true);
        let mut tun_writer = Tun::new(writer, 1500, true);

        let mut packet = [0u8; 20];
        packet[0] = 4 << 4;
        let msg = b"hello";

        for (p, m) in packet.iter_mut().zip(msg) {
            *p = *m;
        }

        tun_writer.write(&packet).unwrap();

        let mut buf = [0u8; 20];
        let len = tun_reader.read(&mut buf).unwrap();

        assert_eq!(len, packet.len());
        assert_eq!(&buf[..len], &packet[..len]);
    }

    #[test]
    fn test_is_ipv6() {
        assert_eq!(is_ipv6(&[0x60]).unwrap(), true);
        assert_eq!(is_ipv6(&[0x45]).unwrap(), false);
        assert!(is_ipv6(&[0x10]).is_err());
        assert!(is_ipv6(&[]).is_err())
    }
}
