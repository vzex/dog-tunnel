pub struct udp_pipe {}
impl udp_pipe {
    async fn dial<'a>(addr: &str, punch_server: &str) -> Result<udp_pipe, &'a str> {
        Ok(udp_pipe {})
    }
    async fn close(self) {}
}
#[cfg(test)]
mod test {
    #[test]
    fn udp_test() {
        println!("this is a test");
    }
}
