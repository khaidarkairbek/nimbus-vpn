use std::{fs::{self, File}, io::{Error, Read, Write}, mem, os::fd::{AsRawFd, FromRawFd}, path::Path, process};
use libc::{self, __c_anonymous_ifr_ifru};
use anyhow::{Result, bail, anyhow};
//use tokio::fs::File;
//use tokio::io::{self, AsyncReadExt, AsyncWriteExt};

use crate::error::{
    TunInitError::*, 
    TunOperationError::*
};

// The controller address structure is used to establish 
// contact between a user client and a kernel controller.
// As defined at https://developer.apple.com/documentation/kernel/sockaddr_ctl
#[repr(C)]
pub struct SockAddrCtl {
    pub sc_len : u8,   // The length of the structure
    pub sc_family : u8,  // AF_SYSTEM.
    pub ss_sysaddr : u16,  // AF_SYS_KERNCONTROL
    pub sc_id : u32,   // Controller unique identifier.
    pub sc_unit : u32,   // Developer private unit number
    pub sc_reserved : [u32; 5] // Reserved, must be set to zero
}
// This structure is used with the CTLIOCGINFO ioctl to
// translate from a kernel control name to a control id.
// As defined at https://developer.apple.com/documentation/kernel/ctl_info
#[derive(Debug)]
#[repr(C)]
pub struct CtlInfo {
    pub ctl_id : u32,   // Kernel Controller Id
    pub ctl_name : [u8; 96]   // Kernel Controller Name
}

#[derive(Debug)]
pub struct TunDevice {
    pub file : File, 
    pub id : u8
}

const MTU: &'static str = "1380"; 
impl TunDevice {
    #[cfg(target_os = "macos")]
    // Creates the TUN device of specified number
    pub fn create(tun_num: Option<u8>) -> Result<TunDevice>{
        match tun_num {
            None => {
                let mut num = 0; 
                loop {

                    if num == 255 {
                        panic!("No available space for new tun device!")
                    }
            
                    match TunDevice::create(Some(num)) {
                        Ok(tun) =>  break Ok(tun),
                        Err(_) => num += 1,
                    }
                }
            }, 
            Some(tun_num) => {
                const DOMAIN: i32 = libc::PF_SYSTEM; // Protocol domain to be used
                const TY: i32 = libc::SOCK_DGRAM;   // Communication semantics
                const PROTOCOL: i32 = libc::SYSPROTO_CONTROL;  // Protocol to be used for the socket

                
                // Create a socket (endpoint for communication)
                let sock_fd = unsafe {libc::socket(DOMAIN, TY, PROTOCOL)};

                if sock_fd == -1 {
                    bail!(TunSocketOpenError(Error::last_os_error()));
                };

                let file = unsafe{std::fs::File::from_raw_fd(sock_fd)};

                // Kernel Control Info
                let mut ctl_info: CtlInfo = CtlInfo {
                    ctl_id : 0, 
                    ctl_name : [0u8; 96]
                };

                unsafe {
                    libc::memset(&mut ctl_info as *mut _ as *mut libc::c_void, 0, mem::size_of::<CtlInfo>() as libc::size_t); // Clear the kernel info by modifying the memory
                    let ctl_name = std::ffi::CString::new("com.apple.net.utun_control").unwrap();
                    libc::strncpy(ctl_info.ctl_name.as_mut_ptr() as *mut libc::c_char, ctl_name.as_ptr(), 96);  // Set the kernel control name
                }; 

                if unsafe {libc::ioctl(file.as_raw_fd(), libc::CTLIOCGINFO, &mut ctl_info)} == -1 {  // Getting kernel control id, break if not succesfull
                    bail!(KernelCtrlIdError(Error::last_os_error()));
                };

                // Instantiate the kernel control connection data
                let sockaddr_ctl: SockAddrCtl = SockAddrCtl {   
                    sc_len : mem::size_of::<SockAddrCtl>() as u8, 
                    sc_family : DOMAIN as u8,
                    ss_sysaddr : libc::AF_SYS_CONTROL as u16,
                    sc_unit : {tun_num + 1}  as u32, 
                    sc_id : ctl_info.ctl_id,
                    sc_reserved : [0; 5]
                };

                // Connect to the kernel control
                if unsafe {libc::connect(file.as_raw_fd(), &sockaddr_ctl as *const _ as *const libc::sockaddr, mem::size_of_val(&sockaddr_ctl) as u32)} == -1 {
                    bail!(TunSocketConnectError(Error::last_os_error()));
                }

                if unsafe {libc::fcntl(file.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK)} == -1 {
                    bail!(NonBlockError(Error::last_os_error()));
                }

                println!("Tun connected ");
                Ok(TunDevice {
                    file : file, 
                    id : tun_num
                })
            }
        }

    }

    #[cfg(target_os = "linux")]
    pub fn create(tun_num: Option<u8>) -> Result<TunDevice> {
        match tun_num {
            None => {
                let mut num = 1; 
                loop {

                    if num == 255 {
                        panic!("No available space for new tun device!")
                    }
            
                    match TunDevice::create(Some(num)) {
                        Ok(tun) =>  break Ok(tun),
                        Err(_) => num += 1,
                    }
                }
            }, 
            Some(tun_num) => {
                // https://docs.kernel.org/networking/tuntap.html
                // https://backreference.org/2010/03/26/tuntap-interface-tutorial/
                // https://john-millikin.com/creating-tun-tap-interfaces-in-linux
                let tun_path = Path::new("/dev/net/tun"); 
                let file = fs::OpenOptions::new().read(true).write(true).open(tun_path)?; 

                let mut ifr = libc::ifreq {
                    ifr_name : [0; libc::IFNAMSIZ], 
                    ifr_ifru : __c_anonymous_ifr_ifru {
                        ifru_flags : 0
                    }
                }; 
                unsafe{
                    libc::memset(&mut ifr as *mut _ as *mut libc::c_void, 0, mem::size_of::<libc::ifreq>() as libc::size_t); // Clear the kernel info by modifying the memory
                }

                const IFF_TUN: libc::c_short = 0x0001;
                const IFF_NO_PI: libc::c_short = 0x1000;
                ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

                let tun_name = format!("tun{}", tun_num); 
                let mut buffer  = Vec::<libc::c_char>::new(); 
                for byte in tun_name.as_bytes().into_iter() {
                    buffer.push(*byte as libc::c_char)
                }
                ifr.ifr_name[..tun_name.len()].copy_from_slice(&buffer); 

                // #define TUNSETIFF     _IOW('T', 202, int)
                const TUN_IOC_MAGIC: u8 = b'T' as u8;
                const TUN_IOC_SET_IFF: u8 = 202;
                const TUNSETIFF: libc::c_ulong = 0x400454ca;
                if unsafe {libc::ioctl(file.as_raw_fd(), TUNSETIFF, &mut ifr)} == -1 {
                    bail!(KernelCtrlIdError(Error::last_os_error()))
                }

                println!("Tun connected ");
                Ok(TunDevice {
                    file : file, 
                    id : tun_num
                })
            }
        }
    }

    #[cfg(target_os = "macos")]
    // Brings the tun device up and sets it up using ifconfig to given ip address and MTU constant
    pub fn up(&self, server_client_id: Option<u8>) {
        let id = match server_client_id {
            Some(id) => id, 
            None => 1
        };
        //  Assign IP addresses to TUN and bring it up
        let mut status = process::Command::new("ifconfig").arg(format!("utun{}", self.id)).arg(format!("10.20.20.{}", id)).arg("10.20.20.1").status().unwrap(); 
        assert!(status.success()); 

        // Setting MTU (Maximum Transmission Unit) value to 1380, which is a standard for VPN application
        status = process::Command::new("ifconfig").arg(format!("utun{}", self.id)).arg("mtu").arg(MTU).arg("up").status().unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "linux")]
    // Brings the tun device up and sets it up using ifconfig to given ip address and MTU constant
    pub fn up(&self, server_client_id: Option<u8>) {
        let id = match server_client_id {
            Some(id) => id, 
            None => 1
        };
        let mut status = process::Command::new("ip").arg("addr").arg("add").arg(format!("10.20.20.{}/24", id)).arg("dev").arg(format!("tun{}", self.id)).status().unwrap(); 
        assert!(status.success());

        // Setting MTU (Maximum Transmission Unit) value to 1380, which is a standard for VPN application
        status = process::Command::new("ip").arg("link").arg("set").arg("dev").arg(format!("tun{}", self.id)).arg("mtu").arg(MTU).arg("up").status().unwrap();
        assert!(status.success());
    }

    #[cfg(target_os = "macos")]
    // Write the data into tun device from the buffer, returns the length of the written data or Error
    pub fn write(&mut self, buffer : &[u8]) -> Result<usize>{
        let mut packet = match buffer[0] & 0xf {
            6 => vec![0, 0, 0, 10],   // 4 byte header for ipv6 packet on MacOS
            _ => vec![0, 0, 0, 2]     // 4 byte header for ipv4 packet on MacOS
        }; 
        
        packet.write_all(buffer)?;

        match self.file.write(&packet) {
            Ok(len) => if len > 4 { Ok(len - 4) } else { Ok(0) }, 
            Err(e) => bail!(TunWriteError(e))
        }
    }

    #[cfg(target_os = "linux")]
    // Write the data into tun device from the buffer, returns the length of the written data or Error
    pub fn write(&mut self, buffer : &[u8]) -> Result<usize>{
        self.file.write(buffer).map_err(|e| anyhow!(TunWriteError(e)))
    }

    #[cfg(target_os = "macos")]
    // Read the data from tun device into the buffer, returns the length of the read data or Error
    pub fn read(&mut self, buffer : &mut [u8]) -> Result<usize> {

        let mut packet = [0; 2000];  // the regular MTU is about 1500, so 2000 should be sufficient

        match self.file.read(&mut packet) {
            Ok(len) => {
                if len <= 4 {
                    // Not enough data read to constitute a valid packet
                    return Ok(0)
                };
                let data = &packet[4..len];   // removing the 4 byte header, signifying ipv6 or ipv4 packet
                let data_len = len - 4;
                buffer[..data_len].clone_from_slice(data);  // writing the data into the beginning of the buffer
                Ok(data_len)
            },
            Err(e) => bail!(TunReadError(e))
        }
    }

    #[cfg(target_os = "linux")]
    // Read the data from tun device into the buffer, returns the length of the read data or Error
    pub fn read(&mut self, buffer : &mut [u8]) -> Result<usize> {
        self.file.read(buffer).map_err(|e| anyhow!(TunReadError(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_up_tun_test() {

        let tun = TunDevice::create(None).unwrap();
    
        tun.up(None);
    
        println!("Created tun device: {:?}", tun);

        let status = process::Command::new("ifconfig").arg(format!("utun{}", tun.id)).output().unwrap().status; 
        assert!(status.success())
    }
}