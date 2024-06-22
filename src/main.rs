use std::{io::{Read, Write, Error}, fs::File, mem, os::fd::{AsRawFd, FromRawFd}, process};
use libc;

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

// Creates the TUN device of specified number
pub fn create(tun_num: &u8) -> Result<File, Error>{

    const DOMAIN: i32 = libc::PF_SYSTEM; // Protocol domain to be used
    const TY: i32 = libc::SOCK_DGRAM;   // Communication semantics
    const PROTOCOL: i32 = libc::SYSPROTO_CONTROL;  // Protocol to be used for the socket

    
    // Create a socket (endpoint for communication)
    let sock_fd = unsafe {libc::socket(DOMAIN, TY, PROTOCOL)};

    if sock_fd == -1 {
        eprintln!("Problem opening a socket"); 
        return Err(Error::last_os_error());
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
        eprintln!("Problem getting kernel control id");
        return Err(Error::last_os_error());
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
        eprintln!("Problem connecting to the socket");
        return Err(Error::last_os_error());
    }

    println!("Connected and finished");
    Ok(file)
}

// Brings the tun device up and sets it up using ifconfig to given ip address and MTU constant
pub fn up(tun : &TunDevice) {

    //  Assign IP addresses to TUN and bring it up
    let mut status = process::Command::new("ifconfig").arg(format!("utun{}", tun.id)).arg("69.69.69.11").arg("69.69.69.12").status().unwrap(); 
    assert!(status.success()); 

    // Setting MTU (Maximum Transmission Unit) value to 1380, which is a standard for VPN application
    status = process::Command::new("ifconfig").arg(format!("utun{}", tun.id)).arg("mtu").arg(MTU).status().unwrap();
    assert!(status.success());
}


// Write the data into tun device from the buffer, returns the length of the written data or Error
pub fn write(tun : &mut TunDevice, buffer : &[u8]) -> Result<usize, std::io::Error>{

    let mut packet = match buffer[0] & 0xf {
        6 => vec![0, 0, 0, 10],   // 4 byte header for ipv6 packet on MacOS
        _ => vec![0, 0, 0, 2]     // 4 byte header for ipv4 packet on MacOS
    }; 
    
    packet.write_all(buffer)?;

    match tun.file.write(&packet) {
        Ok(len) => if len > 4 { Ok(len - 4) } else { Ok(0) }, 
        Err(e) => Err(e)
    }
}


// Read the data from tun device into the buffer, returns the length of the read data or Error
pub fn read(tun : &mut TunDevice, buffer : &mut [u8]) -> Result<usize, std::io::Error> {

    let mut packet = [0; 2000];  // the regular MTU is about 1500, so 2000 should be sufficient

    match tun.file.read(&mut packet) {
        Ok(len) => {
            let data = &packet[4..len];   // removing the 4 byte header, signifying ipv6 or ipv4 packet
            buffer[..len-4].clone_from_slice(data);  // writing the data into the beginning of the buffer
            if len > 4 { Ok(len - 4) } else { Ok(0) }}  
        Err(e) => Err(e)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_up_tun_test() {

        let mut tun_num = 0; 
        let tun = loop {
    
            if tun_num == 255 {
                panic!("No available space for new tun device!")
            }
    
            match create(&tun_num) {
                Ok(tun_file) =>  break TunDevice{file : tun_file, id : tun_num},
                Err(_) => tun_num += 1,
            }
        };
    
        up(&tun);
    
        println!("Created tun device: {:?}", tun);

        let status = process::Command::new("ifconfig").arg(format!("utun{}", tun.id)).output().unwrap().status; 
        assert!(status.success())
    }
}

fn main() {

}