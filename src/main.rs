use std::{mem, os::fd::{AsRawFd, FromRawFd}, process};
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

fn main() {

    let tun_num: u8 = 150 ; 

    const DOMAIN: i32 = libc::PF_SYSTEM; // Protocol domain to be used
    const TY: i32 = libc::SOCK_DGRAM;   // Communication semantics
    const PROTOCOL: i32 = libc::SYSPROTO_CONTROL;  // Protocol to be used for the socket

    
    // Create a socket (endpoint for communication)
    let sock_fd = unsafe {libc::socket(DOMAIN, TY, PROTOCOL)};

    if sock_fd == -1 {
        eprintln!("Problem opening a socket"); 
        process::exit(1);
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
        process::exit(1);
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
        process::exit(1);
    }

    println!("Connected and finished");
    process::exit(0);
}