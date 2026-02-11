use bytes::BytesMut;
use std::cell::RefCell;

thread_local! {
    static BUFFER_POOL: RefCell<Vec<BytesMut>> = RefCell::new(Vec::with_capacity(16));
}

/// 从池中获取一个 16KB 缓存区
pub fn acquire_buffer() -> BytesMut {
    BUFFER_POOL.with(|pool| {
        pool.borrow_mut()
            .pop()
            .unwrap_or_else(|| BytesMut::with_capacity(16384))
    })
}

/// 将缓存区归还到池中
pub fn release_buffer(mut buf: BytesMut) {
    if buf.capacity() >= 16384 {
        buf.clear();
        BUFFER_POOL.with(|pool| {
            let mut p = pool.borrow_mut();
            if p.len() < 16 {
                p.push(buf);
            }
        });
    }
}
