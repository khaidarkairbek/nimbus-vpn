use mio::{Events, Poll as Mio_Poll, Interest, Token};
use mio::unix::SourceFd;
use tun::TunDevice;
use mio::net::UdpSocket;
use std::os::fd::AsRawFd; 

mod tun;

pub struct Executor {
    pub clients: Vec<UdpSocket>, 
    pub poll: Mio_Poll, 
    pub events: Events,
}

fn main() {

    let mut poll = Mio_Poll::new().unwrap();

    let mut events = Events::with_capacity(1024); 

    let mut sock_fd = UdpSocket::bind("127.0.0.1:0".parse().unwrap()).unwrap();

    let mut tun = TunDevice::create(100).unwrap();
    tun.up();
    let mut tun_raw_fd = tun.file.as_raw_fd(); 

    let mut tun_fd = SourceFd(&mut tun_raw_fd); 

    poll.registry().register(&mut sock_fd, Token(1), Interest::READABLE).unwrap();

    poll.registry().register(&mut tun_fd, Token(2), Interest::READABLE).unwrap();

    loop {
        poll.poll(&mut events, None).unwrap();
        for event in &events {
            match event.token() {
                Token(1) => {
                    let mut buffer = [0; 2000]; 
                    let (len, from_addr) = sock_fd.recv_from(&mut buffer).unwrap();
                    println!("Socket received {:?} from {:?}", &buffer[..len], from_addr); 
                }, 
                Token(2) => {
                    let mut buffer = [0; 2000]; 
                    let len = tun.read(&mut buffer).unwrap();
                    println!("TUN received {:?}", &buffer[..len]); 
                },
                Token(_) => (),
            }
        }
    }

}