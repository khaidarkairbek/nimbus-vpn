use std::io::{Error, ErrorKind, Result};
use std::os::fd::{AsRawFd, IntoRawFd, RawFd};

#[derive(Debug)]
pub struct Fd {
    raw: RawFd,
    close_fd_on_drop: bool,
}

impl Fd {
    pub fn new(value: RawFd, close_fd_on_drop: bool) -> Result<Self> {
        if value < 0 {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "Invalid file descriptor!",
            ));
        };

        Ok(Fd {
            raw: value,
            close_fd_on_drop,
        })
    }

    pub fn set_nonblocking(&self) -> Result<()> {
        let flags = unsafe { libc::fcntl(self.raw, libc::F_GETFL) };
        if flags < 0 {
            return Err(Error::last_os_error());
        }

        if unsafe { libc::fcntl(self.raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
            return Err(Error::last_os_error());
        }

        Ok(())
    }

    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        let fd = self.as_raw_fd();

        let amount = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut _, buf.len()) };
        if amount < 0 {
            return Err(Error::last_os_error());
        }

        Ok(amount as usize)
    }

    pub fn write(&self, buf: &[u8]) -> Result<usize> {
        let fd = self.as_raw_fd();

        let amount = unsafe { libc::write(fd, buf.as_ptr() as *const _, buf.len()) };

        if amount < 0 {
            return Err(Error::last_os_error());
        }

        Ok(amount as usize)
    }
}

impl AsRawFd for Fd {
    fn as_raw_fd(&self) -> RawFd {
        self.raw
    }
}

impl IntoRawFd for Fd {
    fn into_raw_fd(mut self) -> RawFd {
        let fd = self.raw;
        self.raw = -1;
        fd
    }
}

impl Drop for Fd {
    fn drop(&mut self) {
        if self.close_fd_on_drop && self.raw >= 0 {
            unsafe { libc::close(self.raw) };
        }
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
    fn test_new_valid_fd() {
        let [fd_1, _] = setup_fds();

        let fd = Fd::new(fd_1, false).unwrap();
        assert_eq!(fd.raw, fd_1);
    }

    #[test]
    fn test_new_invalid_fd() {
        let fd = Fd::new(-1, true);
        assert!(fd.is_err());
        assert_eq!(fd.unwrap_err().kind(), ErrorKind::InvalidData);
    }

    #[test]
    fn test_set_non_block_valid() {
        let [fd_1, _] = setup_fds();

        let fd = Fd::new(fd_1, true).unwrap();

        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };

        assert_eq!(flags & libc::O_NONBLOCK, 0);

        fd.set_nonblocking().unwrap();

        let flags = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFL) };

        assert_ne!(flags & libc::O_NONBLOCK, 0);
    }

    #[test]
    fn test_write_and_read() {
        let [fd_1, fd_2] = setup_fds();

        let reader = Fd::new(fd_1, true).unwrap();
        let writer = Fd::new(fd_2, true).unwrap();

        let buf = b"hello";

        writer.write(buf).unwrap();

        let mut buf = [0u8; 5];
        reader.read(&mut buf).unwrap();

        assert_eq!(&buf, b"hello");
    }

    #[test]
    fn test_drop() {
        let [fd_1, _] = setup_fds();

        let fd = Fd::new(fd_1, true).unwrap();

        drop(fd);

        let flags = unsafe { libc::fcntl(fd_1, libc::F_GETFD) };

        assert_eq!(flags, -1);

        let [fd_1, _] = setup_fds();

        let fd = Fd::new(fd_1, false).unwrap();

        drop(fd);

        let flags = unsafe { libc::fcntl(fd_1, libc::F_GETFD) };

        assert_ne!(flags, -1);
    }
}
