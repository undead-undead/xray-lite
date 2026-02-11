use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tracing::{debug, error};

/// 代理连接
pub struct ProxyConnection<C, R> {
    client_stream: C,
    remote_stream: R,
}

impl<C, R> ProxyConnection<C, R> 
where 
    C: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: AsyncRead + AsyncWrite + Unpin + Send + 'static
{
    /// 创建新的代理连接
    pub fn new(client_stream: C, remote_stream: R) -> Self {
        Self {
            client_stream,
            remote_stream,
        }
    }

    /// 双向数据转发 (带 300s 空闲超时控制)
    pub async fn relay(self) -> Result<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::time::{timeout, Duration};

        debug!("开始双向数据转发 (Custom Relay with 300s idle timeout)");

        let (mut client_read, mut client_write) = tokio::io::split(self.client_stream);
        let (mut remote_read, mut remote_write) = tokio::io::split(self.remote_stream);

        // 闲置超时时间 (5分钟)
        let idle_timeout = Duration::from_secs(300);

        let client_to_remote = async {
            let mut buf = super::pool::acquire_buffer();
            let mut total_bytes = 0;
            let res = async {
                loop {
                    // 优化：大数据负载下 read_buf 会尽量填满，减少系统调用
                    let n = match timeout(idle_timeout, client_read.read_buf(&mut buf)).await {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => {
                            debug!("连接闲置超时 (Client -> Remote)");
                            return Ok(total_bytes);
                        }
                    };

                    if n == 0 { break; }
                    remote_write.write_all(&buf[..n]).await?;
                    total_bytes += n as u64;
                    buf.clear();
                }
                remote_write.shutdown().await?;
                Ok::<u64, std::io::Error>(total_bytes)
            }.await;
            super::pool::release_buffer(buf);
            res
        };

        let remote_to_client = async {
            let mut buf = super::pool::acquire_buffer();
            let mut total_bytes = 0;
            let res = async {
                loop {
                    // 优化：大数据负载下 read_buf 会尽量填满
                    let n = match timeout(idle_timeout, remote_read.read_buf(&mut buf)).await {
                        Ok(Ok(n)) => n,
                        Ok(Err(e)) => return Err(e),
                        Err(_) => {
                            debug!("连接闲置超时 (Remote -> Client)");
                            return Ok(total_bytes);
                        }
                    };

                    if n == 0 { break; }
                    client_write.write_all(&buf[..n]).await?;
                    total_bytes += n as u64;
                    buf.clear();
                }
                client_write.shutdown().await?;
                Ok::<u64, std::io::Error>(total_bytes)
            }.await;
            super::pool::release_buffer(buf);
            res
        };

        // 使用 join 运行两个方向，任何一方正常结束或超时，都会触发联动检测
        // 注意：我们不需要 select!，因为我们希望两个方向尽可能独立运行，
        // 只有当两个方向都结束或其中一方出错/超时，整个 relay 才算结束。
        match tokio::try_join!(client_to_remote, remote_to_client) {
            Ok((c2r, r2c)) => {
                debug!("连接正常结束: 客户端->远程 {} 字节, 远程->客户端 {} 字节", c2r, r2c);
                Ok(())
            }
            Err(e) => {
                let error_kind = e.kind();
                match error_kind {
                    std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof => {
                        debug!("连接异常断开: {}", e);
                        Ok(())
                    }
                    _ => {
                        error!("连接转发错误: {:?} - {}", error_kind, e);
                        Err(e.into())
                    }
                }
            }
        }
    }
}

/// 连接管理器
#[derive(Clone)]
pub struct ConnectionManager {
    /// 活跃连接数
    active_connections: std::sync::Arc<std::sync::atomic::AtomicUsize>,
}

impl ConnectionManager {
    /// 创建新的连接管理器
    pub fn new() -> Self {
        Self {
            active_connections: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }
    }



    /// 处理新连接
    pub async fn handle_connection<T>(
        &self,
        client_stream: T,
        remote_stream: TcpStream,
    ) -> Result<()> 
    where
        T: AsyncRead + AsyncWrite + Unpin + Send + 'static
    {
        // 增加活跃连接计数
        self.active_connections
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        let active_connections = self.active_connections.clone();
        let connection = ProxyConnection::new(client_stream, remote_stream);
        
        // 直接在当前任务中等待转发完成
        // 注意：调用者 (如 server.rs 或 h2.rs) 已经在一个独立的 tokio task 中运行了，所以这里不需要再 spawn
        let result = connection.relay().await;
        
        // 减少活跃连接计数
        active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);

        if let Err(e) = result {
            error!("连接处理失败: {}", e);
            return Err(e);
        }

        Ok(())
    }
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_manager_creation() {
        let _manager = ConnectionManager::new();
        // assert_eq!(manager.active_count(), 0);
    }
}
