use async_trait::async_trait;
use std::io;

pub struct PipeDialInfo {}
pub struct PipeListenInfo {}

pub trait PipeTrait {
    fn close(self);
}
#[async_trait]
pub trait PipeClientTrait {
    type Output;
    //fn dial(pipe_info: PipeDialInfo) -> Result<Self::Output, &'static str>;
    async fn send(&mut self, buf: &[u8]) -> io::Result<usize>;
    async fn recv(&mut self) -> Option<Vec<u8>>;
}

#[async_trait]
pub trait PipeServerTrait<T, U> {
    type Output;
    //fn listen(pipe_info: PipeListenInfo) -> Result<Self::Output, &'static str>;
    async fn listen(
        addr: &str,
        on_accept: fn(T),
        channel_size: usize,
    ) -> Result<U, Box<dyn std::error::Error>>;
}
