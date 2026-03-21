use std::io::{Error, ErrorKind, Read, Result, Write};
use std::net::Ipv4Addr;
use std::os::fd::{AsRawFd, RawFd};
use std::{mem, process};

use crate::tun::config::{Configuration, DEFAULT_MTU};
use crate::tun::fd::Fd;
use crate::tun::tun::Tun;

pub mod config;
mod fd;
mod tun;

#[derive(Debug)]
pub struct TunDevice {
    tun_name: String,
    tun: Tun,
    ctl_fd: Fd,
    route: Option<Route>,
    is_enabled_: bool
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Route {
    addr: Ipv4Addr,
    netmask: Ipv4Addr,
    dest: Ipv4Addr,
}

impl TunDevice {
    #[cfg(target_os = "macos")]
    pub fn new(config: &Configuration) -> Result<Self> {
        let mtu = config.mtu.unwrap_or(DEFAULT_MTU);

        let id = if let Some(tun_name) = config.tun_name.as_ref() {
            if tun_name.len() >= libc::IFNAMSIZ {
                return Err(Error::new(ErrorKind::InvalidData, "Too long tun name"));
            }

            if !tun_name.starts_with("utun") {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid tun name"));
            }

            tun_name[4..].parse::<u32>().map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid tun name"))? + 1_u32
        } else {
            0_u32
        };

        let mut device = unsafe {
            const DOMAIN: i32 = libc::PF_SYSTEM;
            const TY: i32 = libc::SOCK_DGRAM;
            const PROTOCOL: i32 = libc::SYSPROTO_CONTROL;

            let sock_fd = libc::socket(DOMAIN, TY, PROTOCOL);
            if sock_fd < 0 {
                return Err(Error::last_os_error());
            }

            let tun = Fd::new(sock_fd, true)?;

            let mut ctl_info = libc::ctl_info {
                ctl_id: 0,
                ctl_name: [0; libc::MAX_KCTL_NAME],
            };

            libc::memset(
                &mut ctl_info as *mut _ as *mut libc::c_void,
                0,
                mem::size_of::<libc::ctl_info>() as libc::size_t,
            );
            let ctl_name = std::ffi::CString::new("com.apple.net.utun_control").unwrap();
            libc::strncpy(
                ctl_info.ctl_name.as_mut_ptr() as *mut libc::c_char,
                ctl_name.as_ptr(),
                libc::MAX_KCTL_NAME,
            );

            if libc::ioctl(tun.as_raw_fd(), libc::CTLIOCGINFO, &mut ctl_info) == -1 {
                return Err(Error::last_os_error());
            };

            let sockaddr_ctl: libc::sockaddr_ctl = libc::sockaddr_ctl {
                sc_len: mem::size_of::<libc::sockaddr_ctl>() as u8,
                sc_family: DOMAIN as u8,
                ss_sysaddr: libc::AF_SYS_CONTROL as u16,
                sc_unit: id,
                sc_id: ctl_info.ctl_id,
                sc_reserved: [0; 5],
            };

            if libc::connect(
                tun.as_raw_fd(),
                &sockaddr_ctl as *const _ as *const libc::sockaddr,
                mem::size_of_val(&sockaddr_ctl) as u32,
            ) == -1
            {
                return Err(Error::last_os_error());
            }

            let mut tun_name = [0u8; 64];
            let mut len: libc::socklen_t = tun_name.len() as libc::socklen_t; 

            if libc::getsockopt(
                tun.as_raw_fd(),
                PROTOCOL,
                libc::UTUN_OPT_IFNAME,
                &mut tun_name as *mut _ as *mut libc::c_void,
                &mut len,
            ) == -1
            {
                return Err(Error::last_os_error());
            }

            let ctl_fd = Fd::new(libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0), true)?;

            TunDevice {
                tun_name: {
                    let len = tun_name
                        .iter()
                        .position(|&b| b == 0)
                        .unwrap_or(tun_name.len());
                    std::str::from_utf8(&tun_name[..len])
                        .map_err(|_| {
                            Error::new(ErrorKind::InvalidData, "Invalid UTF-8 for tun name")
                        })?
                        .to_string()
                },
                tun: Tun::new(tun, mtu, config.platform_config.packet_information),
                route: None,
                ctl_fd,
                is_enabled_: false
            }
        };

        if let Some(ip) = config.address {
            device.set_address(ip)?;
        }

        if let Some(ip) = config.destination {
            device.set_destination(ip)?;
        }

        if let Some(ip) = config.broadcast {
            device.set_broadcast(ip)?;
        }

        if let Some(ip) = config.netmask {
            device.set_netmask(ip)?;
        }

        if let Some(mtu) = config.mtu {
            device.set_mtu(mtu)?;
        } else {
            device.set_mtu(DEFAULT_MTU)?;
        }

        if let Some(enabled) = config.enabled {
            device.enable(enabled)?;
        } else {
            device.enable(true)?;
        }

        device.set_nonblock()?;

        device.set_alias(
            config.address.unwrap_or(Ipv4Addr::new(10, 0, 0, 1)),
            config.destination.unwrap_or(Ipv4Addr::new(10, 0, 0, 2)),
            config.netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 255)),
            config.platform_config.enable_routing,
        )?;

        Ok(device)
    }

    #[cfg(target_os = "linux")]
    pub fn new(config: &Configuration) -> Result<Self> {
        let mtu = config.mtu.unwrap_or(DEFAULT_MTU);

        let id = if let Some(tun_name) = config.tun_name.as_ref() {
            if tun_name.len() >= libc::IFNAMSIZ {
                return Err(Error::new(ErrorKind::InvalidData, "Too long tun name"));
            }

            if !tun_name.starts_with("tun") {
                return Err(Error::new(ErrorKind::InvalidData, "Invalid tun name"));
            }

            tun_name[3..].parse::<u32>().map_err(|_| Error::new(ErrorKind::InvalidData, "Invalid tun name"))?
        } else {
            0_u32
        };

        let mut device = unsafe {
            let mut ifr: libc::ifreq = mem::zeroed();
            let tun_name = format!("tun{}", id);

            let mut buffer = Vec::<libc::c_char>::new();
            for byte in tun_name.as_bytes().into_iter() {
                buffer.push(*byte as libc::c_char)
            }

            ifr.ifr_name[..tun_name.len()].copy_from_slice(&buffer);

            const IFF_TUN: libc::c_short = 0x0001;
            const IFF_NO_PI: libc::c_short = 0x1000;
            ifr.ifr_ifru.ifru_flags = IFF_TUN
                | if config.platform_config.packet_information {
                    0
                } else {
                    IFF_NO_PI
                };

            let tun_fd = {
                let fd = libc::open(c"/dev/net/tun".as_ptr() as *const _, libc::O_RDWR);
                let tun_fd = Fd::new(fd, true)?;
                tunsetiff(tun_fd.as_raw_fd(), &mut ifr as *mut _ as *mut i32)?;

                tun_fd
            };

            let ctl_fd = Fd::new(libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0), true)?;

            TunDevice {
                tun_name,
                tun: Tun::new(tun_fd, mtu, config.platform_config.packet_information),
                route: None,
                ctl_fd,
                is_enabled_: false
            }
        };

        let address = config.address.unwrap_or(Ipv4Addr::new(10, 0, 0, 2));
        let destination = config.destination.unwrap_or(Ipv4Addr::new(10, 0, 0, 1));
        let netmask = config.netmask.unwrap_or(Ipv4Addr::new(255, 255, 255, 255));

        device.set_address(address)?;
        device.set_destination(destination)?;
        device.set_netmask(netmask)?;

        if let Some(ip) = config.broadcast {
            device.set_broadcast(ip)?;
        }

        if let Some(mtu) = config.mtu {
            device.set_mtu(mtu)?;
        } else {
            device.set_mtu(DEFAULT_MTU)?;
        }

        if let Some(enabled) = config.enabled {
            device.enable(enabled)?;
        } else {
            device.enable(true)?;
        }

        device.set_nonblock()?;

        if config.platform_config.enable_routing {
            let route = Route {
                addr: address,
                netmask,
                dest: destination,
            };
            device.set_route(route)?;
        }

        Ok(device)
    }

    #[cfg(target_os = "macos")]
    fn set_alias(
        &mut self,
        address: Ipv4Addr,
        broadcast: Ipv4Addr,
        netmask: Ipv4Addr,
        enable_routing: bool,
    ) -> Result<()> {
        let tun_name = self.tun_name.clone();
        let ctl = &self.ctl_fd;

        unsafe {
            let mut req: ifaliasreq = mem::zeroed();

            for (dst, &src) in req.ifra_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            let mut addr: libc::sockaddr_in = mem::zeroed();
            addr.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            addr.sin_family = libc::AF_INET as u8;
            addr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(address.octets()),
            };
            addr.sin_port = 0;
            req.ifra_addr = *(&addr as *const _ as *const libc::sockaddr);

            let mut broadaddr: libc::sockaddr_in = mem::zeroed();
            broadaddr.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            broadaddr.sin_family = libc::AF_INET as u8;
            broadaddr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(broadcast.octets()),
            };
            broadaddr.sin_port = 0;
            req.ifra_broadaddr = *(&broadaddr as *const _ as *const libc::sockaddr);

            let mut mask: libc::sockaddr_in = mem::zeroed();
            mask.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
            mask.sin_family = libc::AF_INET as u8;
            mask.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(netmask.octets()),
            };
            mask.sin_port = 0;
            req.ifra_mask = *(&mask as *const _ as *const libc::sockaddr);

            siocaifaddr(ctl.as_raw_fd(), &req)?;
        }

        if enable_routing {
            let route = Route {
                addr: address,
                netmask,
                dest: broadcast,
            };

            self.set_route(route)?;
        }

        Ok(())
    }

    fn set_route(&mut self, route: Route) -> Result<()> {
        let tun_name = self.tun_name.clone();

        // Delete any previously installed route
        if let Some(prev_route) = &self.route {
            let _ = Self::route_cmd_delete(&prev_route.dest.to_string());
        }

        // Pre-delete the new destination
        let _ = Self::route_cmd_delete(&route.dest.to_string());

        // Add route: traffic destined for peer exits through the TUN interface
        if !Self::route_cmd_add(&route.dest.to_string(), &tun_name)?.success() {
            return Err(Error::new(ErrorKind::Other, "route command failed"));
        }

        self.route = Some(route);

        Ok(())
    }

    #[cfg(target_os = "macos")]
    fn route_cmd_delete(dest: &str) -> Result<process::ExitStatus> {
        process::Command::new("route")
            .args(["-n", "delete", "-host", dest])
            .status()
    }

    #[cfg(target_os = "linux")]
    fn route_cmd_delete(dest: &str) -> Result<process::ExitStatus> {
        process::Command::new("ip")
            .args(["route", "del", &format!("{}/32", dest)])
            .status()
    }

    #[cfg(target_os = "macos")]
    fn route_cmd_add(dest: &str, iface: &str) -> Result<process::ExitStatus> {
        process::Command::new("route")
            .args(["-n", "add", "-host", dest, "-interface", iface])
            .status()
    }

    #[cfg(target_os = "linux")]
    fn route_cmd_add(dest: &str, iface: &str) -> Result<process::ExitStatus> {
        process::Command::new("ip")
            .args(["route", "add", &format!("{}/32", dest), "dev", iface])
            .status()
    }

    pub fn set_nonblock(&self) -> Result<()> {
        self.tun.set_nonblocking()?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn tun_index(&self) -> Result<i32> {
        let cstr = std::ffi::CString::new(self.tun_name.clone())?;
        let index = unsafe { libc::if_nametoindex(cstr.as_ptr()) };
        if index == 0 {
            return Err(Error::last_os_error());
        }
        Ok(index as i32)
    }

    #[allow(dead_code)]
    pub fn tun_name(&self) -> String {
        self.tun_name.clone()
    }

    pub fn enable(&mut self, value: bool) -> Result<()> {
        let ctl = &self.ctl_fd;

        let tun_name = &self.tun_name;
        let mut req: libc::ifreq = unsafe { mem::zeroed() };

        for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
            *dst = src as libc::c_char;
        }

        unsafe {
            siocgifflags(ctl.as_raw_fd(), &mut req)?;

            if value {
                req.ifr_ifru.ifru_flags |= (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            } else {
                req.ifr_ifru.ifru_flags &= !(libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
            }

            siocsifflags(ctl.as_raw_fd(), &req)?;
        }

        self.is_enabled_ = value; 

        Ok(())
    }

    #[allow(dead_code)]
    pub fn address(&self) -> Result<Ipv4Addr> {
        let ctl = &self.ctl_fd;
        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            siocgifaddr(ctl.as_raw_fd(), &mut req)?;

            let address = &*(&req.ifr_ifru.ifru_addr as *const _ as *const libc::sockaddr_in);

            Ok(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)))
        }
    }

    pub fn set_address(&mut self, value: Ipv4Addr) -> Result<()> {
        let ctl = &self.ctl_fd;

        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            let mut sockaddr: libc::sockaddr_in = mem::zeroed();
            #[cfg(target_os = "macos")]
            {
                sockaddr.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
                sockaddr.sin_family = libc::AF_INET as u8;
            }
            #[cfg(target_os = "linux")]
            {
                sockaddr.sin_family = libc::AF_INET as u16;
            }
            sockaddr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(value.octets()),
            };
            sockaddr.sin_port = 0;

            req.ifr_ifru.ifru_addr = *(&sockaddr as *const _ as *const libc::sockaddr);

            siocsifaddr(ctl.as_raw_fd(), &req)?;

            if let Some(mut route) = self.route.as_ref().cloned() {
                route.addr = value;
                self.set_route(route)?;
            }

            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn destination(&self) -> Result<Ipv4Addr> {
        let ctl = &self.ctl_fd;

        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            siocgifdstaddr(ctl.as_raw_fd(), &mut req)?;

            let address = &*(&req.ifr_ifru.ifru_addr as *const _ as *const libc::sockaddr_in);

            Ok(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)))
        }
    }

    pub fn set_destination(&mut self, value: Ipv4Addr) -> Result<()> {
        let ctl = &self.ctl_fd;

        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            let mut sockaddr: libc::sockaddr_in = mem::zeroed();
            #[cfg(target_os = "macos")]
            {
                sockaddr.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
                sockaddr.sin_family = libc::AF_INET as u8;
            }
            #[cfg(target_os = "linux")]
            {
                sockaddr.sin_family = libc::AF_INET as u16;
            }
            sockaddr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(value.octets()),
            };
            sockaddr.sin_port = 0;

            req.ifr_ifru.ifru_addr = *(&sockaddr as *const _ as *const libc::sockaddr);

            siocsifdstaddr(ctl.as_raw_fd(), &req)?;

            if let Some(mut route) = self.route.as_ref().cloned() {
                route.dest = value;
                self.set_route(route)?;
            }

            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn broadcast(&self) -> Result<Ipv4Addr> {
        let ctl = &self.ctl_fd;

        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            siocgifbrdaddr(ctl.as_raw_fd(), &mut req)?;

            let address = &*(&req.ifr_ifru.ifru_addr as *const _ as *const libc::sockaddr_in);

            Ok(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)))
        }
    }

    pub fn set_broadcast(&mut self, value: Ipv4Addr) -> Result<()> {
        let ctl = &self.ctl_fd;

        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            let mut sockaddr: libc::sockaddr_in = mem::zeroed();
            #[cfg(target_os = "macos")]
            {
                sockaddr.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
                sockaddr.sin_family = libc::AF_INET as u8;
            }
            #[cfg(target_os = "linux")]
            {
                sockaddr.sin_family = libc::AF_INET as u16;
            }
            sockaddr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(value.octets()),
            };
            sockaddr.sin_port = 0;

            req.ifr_ifru.ifru_addr = *(&sockaddr as *const _ as *const libc::sockaddr);

            siocsifbrdaddr(ctl.as_raw_fd(), &req)?;

            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn netmask(&self) -> Result<Ipv4Addr> {
        let ctl = &self.ctl_fd;

        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            siocgifnetmask(ctl.as_raw_fd(), &mut req)?;

            let address = &*(&req.ifr_ifru.ifru_addr as *const _ as *const libc::sockaddr_in);

            Ok(Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr)))
        }
    }

    pub fn set_netmask(&mut self, value: Ipv4Addr) -> Result<()> {
        let ctl = &self.ctl_fd;

        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            let mut sockaddr: libc::sockaddr_in = mem::zeroed();
            #[cfg(target_os = "macos")]
            {
                sockaddr.sin_len = mem::size_of::<libc::sockaddr_in>() as u8;
                sockaddr.sin_family = libc::AF_INET as u8;
            }
            #[cfg(target_os = "linux")]
            {
                sockaddr.sin_family = libc::AF_INET as u16;
            }
            sockaddr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(value.octets()),
            };
            sockaddr.sin_port = 0;

            req.ifr_ifru.ifru_addr = *(&sockaddr as *const _ as *const libc::sockaddr);

            siocsifnetmask(ctl.as_raw_fd(), &req)?;

            if let Some(mut route) = self.route.as_ref().cloned() {
                route.netmask = value;
                self.set_route(route)?;
            }

            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn mtu(&self) -> Result<u16> {
        let ctl = &self.ctl_fd;

        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            siocgifmtu(ctl.as_raw_fd(), &mut req)?;

            let mtu = req.ifr_ifru.ifru_mtu as u16;

            Ok(mtu)
        }
    }

    pub fn set_mtu(&mut self, value: u16) -> Result<()> {
        let ctl = &self.ctl_fd;

        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            req.ifr_ifru.ifru_mtu = value as i32;

            siocsifmtu(ctl.as_raw_fd(), &req)?;

            self.tun.set_mtu(value);

            Ok(())
        }
    }

    #[allow(dead_code)]
    pub fn packet_information(&self) -> bool {
        self.tun.packet_info
    }

    #[allow(dead_code)]
    fn is_enabled(&self) -> Result<bool> {
        let ctl = &self.ctl_fd;
        unsafe {
            let tun_name = &self.tun_name;
            let mut req: libc::ifreq = mem::zeroed();

            for (dst, &src) in req.ifr_name.iter_mut().zip(tun_name.as_bytes()) {
                *dst = src as libc::c_char;
            }

            siocgifflags(ctl.as_raw_fd(), &mut req)?;

            let is_enabled = (req.ifr_ifru.ifru_flags
                & (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short)
                != 0;

            Ok(is_enabled)
        }
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        if let Some(route) = &self.route {
            let _ = Self::route_cmd_delete(&route.dest.to_string());
        }
    }
}

impl Read for TunDevice {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize> {
        if !self.is_enabled_ {
            return Err(Error::new(ErrorKind::NotConnected, "Device is not enabled"));
        }
        self.tun.read(buf)
    }
}

impl Write for TunDevice {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        if !self.is_enabled_ {
            return Err(Error::new(ErrorKind::NotConnected, "Device is not enabled"));
        }
        self.tun.write(buf)
    }

    fn flush(&mut self) -> Result<()> {
        self.tun.flush()
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.tun.as_raw_fd()
    }
}

// https://github.com/realthunder/mac-headers/blob/master/usr/include/sys/sockio.h
// Set interface alias address
mod macos_sys {
    #[allow(non_camel_case_types)]
    pub struct ifaliasreq {
        pub ifra_name: [libc::c_char; libc::IFNAMSIZ],
        pub ifra_addr: libc::sockaddr,
        pub ifra_broadaddr: libc::sockaddr,
        pub ifra_mask: libc::sockaddr,
    }
    nix::ioctl_write_ptr!(siocaifaddr, b'i', 26, ifaliasreq);
    // Get ifnet flags
    nix::ioctl_readwrite!(siocgifflags, b'i', 17, libc::ifreq);
    // Set ifnet flags
    nix::ioctl_write_ptr!(siocsifflags, b'i', 16, libc::ifreq);
    // Get ifnet address
    nix::ioctl_readwrite!(siocgifaddr, b'i', 33, libc::ifreq);
    // Set ifnet address
    nix::ioctl_write_ptr!(siocsifaddr, b'i', 12, libc::ifreq);
    // Get p-p address
    nix::ioctl_readwrite!(siocgifdstaddr, b'i', 34, libc::ifreq);
    // Set p-p address
    nix::ioctl_write_ptr!(siocsifdstaddr, b'i', 14, libc::ifreq);
    // Get broadcast address
    nix::ioctl_readwrite!(siocgifbrdaddr, b'i', 35, libc::ifreq);
    // Set broadcast address
    nix::ioctl_write_ptr!(siocsifbrdaddr, b'i', 19, libc::ifreq);
    // Get net addr mask
    nix::ioctl_readwrite!(siocgifnetmask, b'i', 37, libc::ifreq);
    // Set net addr mask
    nix::ioctl_write_ptr!(siocsifnetmask, b'i', 22, libc::ifreq);
    // Get if mtu
    nix::ioctl_readwrite!(siocgifmtu, b'i', 51, libc::ifreq);
    // Set if mtu
    nix::ioctl_write_ptr!(siocsifmtu, b'i', 52, libc::ifreq);
    nix::ioctl_write_ptr!(tunsetiff, b'T', 202, libc::c_int);
}

mod linux_sys {
    // Get ifnet flags
    nix::ioctl_read_bad!(siocgifflags, 0x8913, libc::ifreq);
    // Set ifnet flags
    nix::ioctl_write_ptr_bad!(siocsifflags, 0x8914, libc::ifreq);
    // Get ifnet address
    nix::ioctl_read_bad!(siocgifaddr, 0x8915, libc::ifreq);
    // Set ifnet address
    nix::ioctl_write_ptr_bad!(siocsifaddr, 0x8916, libc::ifreq);
    // Get p-p address
    nix::ioctl_read_bad!(siocgifdstaddr, 0x8917, libc::ifreq);
    // Set p-p address
    nix::ioctl_write_ptr_bad!(siocsifdstaddr, 0x8918, libc::ifreq);
    // Get broadcast address
    nix::ioctl_read_bad!(siocgifbrdaddr, 0x8919, libc::ifreq);
    // Set broadcast address
    nix::ioctl_write_ptr_bad!(siocsifbrdaddr, 0x891a, libc::ifreq);
    // Get net addr mask
    nix::ioctl_read_bad!(siocgifnetmask, 0x891b, libc::ifreq);
    // Set net addr mask
    nix::ioctl_write_ptr_bad!(siocsifnetmask, 0x891c, libc::ifreq);
    // Get if mtu
    nix::ioctl_read_bad!(siocgifmtu, 0x8921, libc::ifreq);
    // Set if mtu
    nix::ioctl_write_ptr_bad!(siocsifmtu, 0x8922, libc::ifreq);
    nix::ioctl_write_ptr!(tunsetiff, b'T', 202, libc::c_int);
}

#[cfg(target_os = "linux")]
use linux_sys::*;
#[cfg(target_os = "macos")]
use macos_sys::*;

#[cfg(test)]
mod tests {
    use std::{net::UdpSocket, time::Duration};

    use super::*;

    fn get_ipv4_addrs(tun_name: &str) -> Result<Vec<Route>> {
        let mut result = Vec::new();
        unsafe {
            let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();

            if libc::getifaddrs(&mut ifap) != 0 {
                return Err(std::io::Error::last_os_error());
            }

            let mut current = ifap;

            while !current.is_null() {
                let ifa = &*current;

                if let Some(name) = std::ffi::CStr::from_ptr(ifa.ifa_name).to_str().ok() {
                    if name == tun_name
                        && !ifa.ifa_addr.is_null()
                        && !ifa.ifa_netmask.is_null()
                        && !ifa.ifa_dstaddr.is_null()
                        && (*ifa.ifa_addr).sa_family as i32 == libc::AF_INET
                    {
                        let addr_in: &libc::sockaddr_in =
                            &*(ifa.ifa_addr as *const libc::sockaddr_in);
                        let ip_addr = Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));

                        let addr_in: &libc::sockaddr_in =
                            &*(ifa.ifa_netmask as *const libc::sockaddr_in);
                        let ip_mask = Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));

                        let addr_in: &libc::sockaddr_in =
                            &*(ifa.ifa_dstaddr as *const libc::sockaddr_in);
                        let ip_dest = Ipv4Addr::from(u32::from_be(addr_in.sin_addr.s_addr));

                        result.push(Route {
                            addr: ip_addr,
                            netmask: ip_mask,
                            dest: ip_dest,
                        })
                    }
                }

                current = (*current).ifa_next;
            }

            libc::freeifaddrs(ifap);
        }

        Ok(result)
    }

    #[test]
    fn test_tun_device_creation() {
        let dev = TunDevice::new(&Configuration::default()).unwrap();

        let ipv4_addresses = get_ipv4_addrs(&dev.tun_name()).unwrap();

        let route = Route {
            addr: dev.address().unwrap(),
            netmask: dev.netmask().unwrap(),
            dest: dev.destination().unwrap(),
        };

        assert!(
            ipv4_addresses.contains(&route),
            "ipv4 routes: {ipv4_addresses:?}, route: {route:?}"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn test_dev_packet_capture() {
        let client_ip: Ipv4Addr = "10.0.0.3".parse().unwrap();
        let destination_ip: Ipv4Addr = "142.250.31.100".parse().unwrap();
        let netmask: Ipv4Addr = "255.255.255.255".parse().unwrap();

        let mut client_config = Configuration::default();
        client_config.destination = Some(destination_ip);
        client_config.address = Some(client_ip);
        client_config.netmask = Some(netmask);
        client_config.platform_config.packet_information = false;
        client_config.enabled = Some(true);

        let mut client_dev = TunDevice::new(&client_config).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(100));

        let socket = UdpSocket::bind(format!("{}:0", client_ip)).unwrap();
        socket.connect(format!("{}:8080", destination_ip)).unwrap();

        let payload = [
            0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25,
            0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33,
            0x34, 0x35, 0x36, 0x37,
        ];
        socket.send(&payload).unwrap();

        let mut tun_buf = [0u8; 1500];
        let mut len_read = None;
        for _ in 0..10 {
            if let Ok(len) = client_dev.read(&mut tun_buf) {
                len_read = Some(len);
                break;
            } else {
                std::thread::sleep(Duration::from_millis(10));
            }
        }

        assert!(len_read.is_some());
        assert_eq!(tun_buf[..4], ((libc::AF_INET) as u32).to_be_bytes());
        assert_eq!(tun_buf[4] >> 4, 4);
        assert_eq!(tun_buf[32..len_read.unwrap()], payload);
    }
}
