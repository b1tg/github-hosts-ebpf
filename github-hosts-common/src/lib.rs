#![no_std]

//#[repr(C)]
//#[derive(Clone, Copy)]
//pub struct BackendPorts {
// 四个端口
// 需要对齐u32，不然会报错过不了verifier：invalid indirect read from stack
//   pub ports: [u16; 4],
//  pub index: usize,
//}

//#[cfg(feature = "user")]
//unsafe impl aya::Pod for BackendPorts {}
