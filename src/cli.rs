use clap::{ Parser, Subcommand}; 


#[derive(Parser)]
#[command(name = "Nimbus VPN", version = "1.0", about = "Command line application for client- and server-side VPN communication")]
pub struct Cli {
    #[command(subcommand)]
    pub mode: Mode
}

#[derive(Subcommand)]
pub enum Mode {
    Client {
        /// Remote address of the server in the following format: 0.0.0.0
        #[arg(short, long)]
        address : String, 
        /// Remote port of the server
        #[arg(short, long)]
        port : u16,
        /// Private key of the client
        #[arg(short, long)]
        key : String,
        /// Local port of the client (Optional)
        #[arg(long)]
        local_port : Option<String>,
        /// The number of tun device to be created and used (Optional)
        #[arg(long)]
        tun_num : Option<u8>,
    }, 
    Server {
        /// Local port of the server
        #[arg(short, long)]
        port : u16,
        /// Private key of the server
        #[arg(short, long)]
        key : String,
        /// The number of tun device to be created and used (Optional)
        #[arg(long)]
        tun_num : Option<u8>,
    }
}


