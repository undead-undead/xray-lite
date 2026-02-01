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

    /// 双向数据转发
    pub async fn relay(mut self) -> Result<()> {
        debug!("开始双向数据转发 (Standard Copy)");

        let (mut cr, mut cw) = tokio::io::split(self.client_stream);
        let (mut rr, mut rw) = tokio::io::split(self.remote_stream);

        let client_to_remote = async {
            let n = tokio::io::copy(&mut cr, &mut rw).await?;
            tokio::io::AsyncWriteExt::shutdown(&mut rw).await?;
            Ok::<u64, std::io::Error>(n)
        };

        let remote_to_client = async {
            let n = tokio::io::copy(&mut rr, &mut cw).await?;
            tokio::io::AsyncWriteExt::shutdown(&mut cw).await?;
            Ok::<u64, std::io::Error>(n)
        };

        match tokio::try_join!(client_to_remote, remote_to_client) {
            Ok((c2r, r2c)) => {
                debug!("连接结束: 客户端->远程 {} 字节, 远程->客户端 {} 字节", c2r, r2c);
                Ok(())
            }
            Err(e) => {
                let error_kind = e.kind();
                match error_kind {
                    std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::BrokenPipe
                    | std::io::ErrorKind::UnexpectedEof => {
                        debug!("连接断开: {}", e);
                        Ok(())
                    }
                    _ => {
                        error!("连接错误: {:?} - {}", error_kind, e);
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

    /// 获取活跃连接数
    pub fn active_count(&self) -> usize {
        self.active_connections
            .load(std::sync::atomic::Ordering::Relaxed)
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
        let manager = ConnectionManager::new();
        assert_eq!(manager.active_count(), 0);
    }
}
