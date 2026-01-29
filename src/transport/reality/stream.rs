use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::crypto::TlsKeys;

/// 封装了 TLS 1.3 加解密的流
pub struct TlsStream<S> {
    stream: S,
    keys: TlsKeys,

    // 输入缓冲区 (存储从 TCP 读到的原始加密数据)
    input_buffer: BytesMut,
    // 解密后的数据缓冲区 (等待被上层消费)
    decrypted_buffer: BytesMut,

    // Write buffer (plaintext accumulation)
    write_buffer: BytesMut,
    // Encrypted output buffer (for handling partial writes)
    encrypted_output_buffer: BytesMut,
    encrypted_output_offset: usize,

    // 序列号
    read_seq: u64,
    write_seq: u64,
}

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream<S> {
    pub fn new(stream: S, keys: TlsKeys) -> Self {
        Self {
            stream,
            keys,
            input_buffer: BytesMut::with_capacity(24 * 1024),
            decrypted_buffer: BytesMut::with_capacity(24 * 1024),
            write_buffer: BytesMut::with_capacity(16 * 1024 + 1024),
            encrypted_output_buffer: BytesMut::new(),
            encrypted_output_offset: 0,
            read_seq: 0,
            write_seq: 0,
        }
    }

    pub fn new_with_buffer(stream: S, keys: TlsKeys, initial_data: BytesMut) -> Self {
        Self {
            stream,
            keys,
            input_buffer: initial_data, // Use provided buffer
            decrypted_buffer: BytesMut::with_capacity(24 * 1024),
            write_buffer: BytesMut::with_capacity(16 * 1024 + 1024),
            encrypted_output_buffer: BytesMut::new(),
            encrypted_output_offset: 0,
            read_seq: 0,
            write_seq: 0,
        }
    }

    /// 尝试从 input_buffer 解析并解密一条 TLS 记录
    fn process_record(&mut self) -> Result<bool> {
        if self.input_buffer.len() < 5 {
            return Ok(false);
        }

        let length = u16::from_be_bytes([self.input_buffer[3], self.input_buffer[4]]) as usize;

        if self.input_buffer.len() < 5 + length {
            return Ok(false);
        }

        // 提取整条记录
        let mut record_data = self.input_buffer.split_to(5 + length);
        let mut header = [0u8; 5];
        header.copy_from_slice(&record_data[..5]);

        // Payload 部分 (Ciphertext)
        let ciphertext = &mut record_data[5..];

        // 解密
        let (content_type, len) =
            self.keys
                .decrypt_client_record(self.read_seq, &header, ciphertext)?;
        self.read_seq += 1;

        // 处理数据
        if content_type == 23 {
            // Application Data
            self.decrypted_buffer.extend_from_slice(&ciphertext[..len]);
        } else if content_type == 21 { // Alert
             // Close notify (100) ?
        }

        Ok(true)
    }

    /// 将 write_buffer 中的明文数据打包加密并发送
    fn flush_write_buffer(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // First, try to drain any pending encrypted output
        while self.encrypted_output_offset < self.encrypted_output_buffer.len() {
            match Pin::new(&mut self.stream).poll_write(
                cx,
                &self.encrypted_output_buffer[self.encrypted_output_offset..],
            ) {
                Poll::Ready(Ok(n)) => {
                    if n == 0 {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "failed to write whole buffer",
                        )));
                    }
                    self.encrypted_output_offset += n;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        // Clear the encrypted buffer once fully written
        if self.encrypted_output_offset > 0 {
            self.encrypted_output_buffer.clear();
            self.encrypted_output_offset = 0;
        }

        // If no plaintext to encrypt, we're done
        if self.write_buffer.is_empty() {
            return Poll::Ready(Ok(()));
        }

        // Encrypt accumulated plaintext
        let encrypted_record =
            match self
                .keys
                .encrypt_server_record(self.write_seq, &self.write_buffer, 23)
            {
                Ok(data) => data,
                Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::Other, e))),
            };

        self.write_seq += 1;
        self.write_buffer.clear();

        // Try to write the encrypted record
        match Pin::new(&mut self.stream).poll_write(cx, &encrypted_record) {
            Poll::Ready(Ok(n)) => {
                if n < encrypted_record.len() {
                    // Partial write: save the rest for later
                    self.encrypted_output_buffer = BytesMut::from(&encrypted_record[n..]);
                    self.encrypted_output_offset = 0;
                    Poll::Ready(Ok(()))
                } else {
                    Poll::Ready(Ok(()))
                }
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                // Socket not ready: save encrypted data for later
                self.encrypted_output_buffer = BytesMut::from(&encrypted_record[..]);
                self.encrypted_output_offset = 0;
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for TlsStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // 1. Drain decrypted buffer
        if !this.decrypted_buffer.is_empty() {
            let len = std::cmp::min(buf.remaining(), this.decrypted_buffer.len());
            buf.put_slice(&this.decrypted_buffer[..len]);
            this.decrypted_buffer.advance(len);
            return Poll::Ready(Ok(()));
        }

        // 2. Loop to read and process records
        loop {
            // Process any pending data
            match this.process_record() {
                Ok(true) => {
                    if !this.decrypted_buffer.is_empty() {
                        let len = std::cmp::min(buf.remaining(), this.decrypted_buffer.len());
                        buf.put_slice(&this.decrypted_buffer[..len]);
                        this.decrypted_buffer.advance(len);
                        return Poll::Ready(Ok(()));
                    }
                    continue;
                }
                Ok(false) => { /* Need more data */ }
                Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
            }

            // Read from underlying stream
            if this.input_buffer.capacity() < 1024 {
                this.input_buffer.reserve(4096);
            }

            let dest = this.input_buffer.chunk_mut();
            // Safety: converting UninitSlice to &mut [MaybeUninit<u8>] manually
            let slice = unsafe {
                std::slice::from_raw_parts_mut(
                    dest.as_mut_ptr() as *mut std::mem::MaybeUninit<u8>,
                    dest.len(),
                )
            };
            let mut read_buf = ReadBuf::uninit(slice);

            match Pin::new(&mut this.stream).poll_read(cx, &mut read_buf) {
                Poll::Ready(Ok(())) => {
                    let n = read_buf.filled().len();
                    if n == 0 {
                        // EOF, but make sure we processed everything
                        if this.input_buffer.is_empty() {
                            return Poll::Ready(Ok(()));
                        } else {
                            // Unexpected EOF inside record
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "Incomplete TLS record",
                            )));
                        }
                    }
                    unsafe {
                        this.input_buffer.advance_mut(n);
                    }
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for TlsStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // 1. Backpressure: If we have pending encrypted data that couldn't be sent,
        // we must wait until it's sent before accepting more plaintext.
        // This prevents memory explosion if the socket is blocked.
        if !this.encrypted_output_buffer.is_empty() {
            match this.flush_write_buffer(cx) {
                Poll::Ready(Ok(())) => {} // Buffer drained, we can continue
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending, // Socket busy, push backpressure to caller
            }
        }

        // 2. Add to plaintext buffer
        this.write_buffer.extend_from_slice(buf);

        // 3. Try to flush immediately
        // IMPORTANT: We ignore Pending here because we already buffered the data.
        // If we return Pending now, the caller will retry with the SAME data, causing duplication!
        // The backpressure in step 1 handles flow control for the NEXT packet.
        match this.flush_write_buffer(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => {
                // We buffered the data but couldn't send it yet.
                // Return Ok(n) so caller knows we accepted it.
                // Next call to poll_write will hit Step 1 and wait if needed.
                Poll::Ready(Ok(buf.len()))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        match this.flush_write_buffer(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.stream).poll_flush(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Try to flush any remaining data
        match this.flush_write_buffer(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.stream).poll_shutdown(cx),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending, // Cannot shutdown if can't flush
        }
    }
}
