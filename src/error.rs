use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TunInitError {
    #[error("Problem opening a socket.")]
    TunSocketOpenError(#[from] io::Error), 
    #[error("Problem getting kernel control ID.")]
    KernelCtrlIdError(io::Error), 
    #[error("Problem connecting to the TUN's socket.")]
    TunSocketConnectError(io::Error), 
    #[error("Problem setting TUN to non-blocking mode.")]
    NonBlockError(io::Error),
}

#[derive(Error, Debug)]
pub enum TunOperationError {
    #[error("Problem writing to TUN device.")]
    TunWriteError(io::Error),
    #[error("Problem reading TUN device.")]
    TunReadError(io::Error), 
}

#[derive(Error, Debug)]
pub enum ServerError {
    #[error("Client address is not specified for a key.")]
    ClientInfoSetError, 
    #[error("Client address is not specified for a key.")]
    ClientInfoGetError,
    #[error("Client info not found in the map.")]
    ClientInfoNotFound, 
    #[error("No available port for new connection.")]
    ServerPortError,
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("Shared secret key not specified for a client.")]
    SharedKeyGetError, 
}

#[derive(Error, Debug)]
pub enum SocketError {
    #[error("Socket send error.")]
    SocketSendToError(String), 
    #[error("Socket read error.")]
    SocketReadError(String), 
    #[error("Socket binding error.")]
    SocketBindError(String)
}

#[derive(Error, Debug)]
pub enum LogicError {
    #[error("Unexpected behavior.")]
    IncorrectRecepientError, 
    #[error("Incorrect message type.")]
    IncorrectMessageError
}

#[derive(Error, Debug)]
pub enum CommError {
    #[error("Mio Poll registry error.")]
    MioRegistryError, 
    #[error("Mio Poll polling error.")]
    MioPollingError, 
    #[error("Mio Poll initiation error.")]
    MioInitError, 
    #[error("Deserialization problem.")]
    DeserialError(String), 
    #[error("Serialization problem.")]
    SerialError(String), 
}

#[derive(Error, Debug)]
pub enum CryptoError {
    #[error("Encryption failed.")]
    EncryptError(String), 
    #[error("Decryption failed.")]
    DecryptError(String),
}
