//extern crate dog_tunnel;
use dogtunnel::pipe::udp_pipe;
use std::io::*;
use std::result::Result::*;

struct Tt {}
impl std::io::Write for Tt {
    fn write(&mut self, buf: &[u8]) -> Result<usize> {
        Ok(0)
    }
    fn flush(&mut self) -> Result<()> {
        Ok(())
    }
}
#[test]
fn init_kcp() {
    let tt = Tt {};
    let mut inst = kcp::Kcp::new(1, tt);
    inst.set_wndsize(128, 128);
}
