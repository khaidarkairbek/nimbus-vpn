use std::net::Ipv4Addr;

pub const DEFAULT_MTU: u16 = 1500;

pub struct Configuration {
    pub tun_name: Option<String>,
    pub platform_config: PlatformConfig,

    pub address: Option<Ipv4Addr>,
    pub destination: Option<Ipv4Addr>,
    pub broadcast: Option<Ipv4Addr>,
    pub netmask: Option<Ipv4Addr>,

    pub mtu: Option<u16>,
    pub enabled: Option<bool>,
}

impl Default for Configuration {
    fn default() -> Self {
        Configuration {
            tun_name: None,
            platform_config: PlatformConfig {
                packet_information: true,
                enable_routing: true,
            },
            address: None,
            destination: None,
            broadcast: None,
            netmask: None,
            mtu: None,
            enabled: None,
        }
    }
}

pub struct PlatformConfig {
    pub packet_information: bool,
    pub enable_routing: bool,
}
