use anyhow::Result;
use tokio::net::TcpStream;
use tokio::io::{AsyncRead, AsyncWrite};
use tracing::{debug, error, info};

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
        debug!("开始双向数据转发");

        // 使用 tokio 的 copy_bidirectional 进行高效的双向转发
        match tokio::io::copy_bidirectional(&mut self.client_stream, &mut self.remote_stream).await
        {
            Ok((client_to_remote, remote_to_client)) => {
                info!(
                    "连接关闭 - 上行: {} 字节, 下行: {} 字节",
                    client_to_remote, remote_to_client
                );
                Ok(())
            }
            Err(e) => {
                error!("数据转发错误: {}", e);
                Err(e.into())
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

        // 在新任务中处理连接
        tokio::spawn(async move {
            let connection = ProxyConnection::new(client_stream, remote_stream);
            
            if let Err(e) = connection.relay().await {
                error!("连接处理失败: {}", e);
            }

            // 减少活跃连接计数
            active_connections.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        });

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
