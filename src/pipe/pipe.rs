pub struct PipeDialInfo {}
pub struct PipeListenInfo {}

pub trait PipeTrait {
    fn close(self);
}
pub trait PipeClientTrait {
    type Output;
    fn dial(pipe_info: PipeDialInfo) -> Result<Self::Output, &'static str>;
}

pub trait PipeServerTrait {
    type Output;
    fn listen(pipe_info: PipeListenInfo) -> Result<Self::Output, &'static str>;
}
