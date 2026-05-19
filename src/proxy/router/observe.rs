use crate::proxy::observe::{ConnectionTracker, Observer, Stats};
use crate::proxy::outbound::{AnyPacket, PacketInfo};
use crate::proxy::{SessionCloser, SourceAddr, TargetAddr};
use async_trait::async_trait;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct ObservedPacket {
    pub inner: Arc<dyn AnyPacket>,
    pub observer: Arc<Observer>,
    pub tracker: Arc<ConnectionTracker>,
    pub outbound_tag: String,
    pub inbound_tag: String,
}

#[async_trait]
impl AnyPacket for ObservedPacket {
    async fn send_to(
        &self,
        buf: bytes::Bytes,
        from: &SourceAddr,
        target: &TargetAddr,
    ) -> anyhow::Result<usize> {
        let n = self.inner.send_to(buf, from, target).await?;
        self.observer
            .on_outbound_traffic(&self.outbound_tag, n as u64, 0);
        self.observer
            .on_inbound_traffic(&self.inbound_tag, n as u64, 0);
        self.tracker.inc_upload(n as u64);
        Ok(n)
    }

    async fn recv_from(&self) -> anyhow::Result<PacketInfo> {
        let (src, dst, data) = self.inner.recv_from().await?;
        let n = data.len();
        self.observer
            .on_outbound_traffic(&self.outbound_tag, 0, n as u64);
        self.observer
            .on_inbound_traffic(&self.inbound_tag, 0, n as u64);
        self.tracker.inc_download(n as u64);
        Ok((src, dst, data))
    }

    fn closer(&self) -> Arc<SessionCloser> {
        self.inner.closer()
    }

    fn get_udp_stats(&self) -> Option<(u64, u64, u64)> {
        let upload = self
            .tracker
            .upload
            .load(std::sync::atomic::Ordering::Relaxed);
        let download = self
            .tracker
            .download
            .load(std::sync::atomic::Ordering::Relaxed);
        Some((upload, download, self.tracker.start_time))
    }
}

impl Drop for ObservedPacket {
    fn drop(&mut self) {
        self.observer.on_outbound_close_udp(&self.outbound_tag);
        self.observer.on_inbound_close_udp(&self.inbound_tag);
        self.observer.remove_connection(&self.tracker.id);
    }
}

pub struct ObservedStream<S> {
    pub inner: S,
    pub stats: Arc<Stats>,
    pub tracker: Arc<ConnectionTracker>,
    pub observer: Arc<Observer>,
    pub is_inbound: bool,
}

impl<S> ObservedStream<S> {
    pub fn new(
        inner: S,
        stats: Arc<Stats>,
        tracker: Arc<ConnectionTracker>,
        observer: Arc<Observer>,
        is_inbound: bool,
    ) -> Self {
        stats.inc_active_tcp();
        Self {
            inner,
            stats,
            tracker,
            observer,
            is_inbound,
        }
    }
}

impl<S> Drop for ObservedStream<S> {
    fn drop(&mut self) {
        self.stats.dec_active_tcp();
        self.observer.remove_connection(&self.tracker.id);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for ObservedStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let after = buf.filled().len();
                let n = (after - before) as u64;
                if n > 0 {
                    if self.is_inbound {
                        self.stats.inc_upload(n);
                        self.tracker.inc_upload(n);
                    } else {
                        self.stats.inc_download(n);
                        self.tracker.inc_download(n);
                    }
                }
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ObservedStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                let n_u64 = n as u64;
                if n_u64 > 0 {
                    if self.is_inbound {
                        self.stats.inc_download(n_u64);
                        self.tracker.inc_download(n_u64);
                    } else {
                        self.stats.inc_upload(n_u64);
                        self.tracker.inc_upload(n_u64);
                    }
                }
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
