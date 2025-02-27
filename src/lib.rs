use std::io;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use rand::Rng;
use rustls::pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, Interest};
use tokio::net::{TcpStream, ToSocketAddrs};
use tokio::task::JoinHandle;
use tokio::time::timeout;

static RUSTLS_CLIENT_CONFIG: LazyLock<Arc<rustls::ClientConfig>> =
    LazyLock::new(|| {
        let store = rustls::RootCertStore::from_iter(
            webpki_roots::TLS_SERVER_ROOTS
                .iter()
                .cloned());
        let mut config = rustls::ClientConfig::builder()
            .with_root_certificates(store)
            .with_no_client_auth();
        config.resumption = rustls::client::Resumption::disabled();
        Arc::new(config)
    });

const TLS_RANDOM_MARKER_OFFSET: usize = 4;

async fn read_tls_packet<T: AsyncRead + Unpin>(stream: &mut T) -> io::Result<Vec<u8>> {
    let t = stream.read_u8().await?;
    let v = stream.read_u16().await?;
    let l = stream.read_u16().await?;

    let mut data = vec![0u8; l as usize + 5];
    data[0] = t;
    data[1..3].copy_from_slice(&v.to_be_bytes());
    data[3..5].copy_from_slice(&l.to_be_bytes());
    stream.read_exact(&mut data[5..]).await?;
    Ok(data)
}

#[cfg(not(doctest))]
/// Sends some data over a [`TcpStream`] in a way such that DPI detects it as a usual HTTPS connection
/// to a website (client side)
///
/// **`stream` must be connected to a server doing [`tls_handshake_as_server`]**
///
/// **To protect against replay attacks, you must negotiate tls_random_marker before calling this method
/// and never reuse it again**
///
/// Example usage:
/// ```
/// use tokio::net::TcpStream;
/// use utls_rs::tls_handshake_as_client;
///
/// async {
///     let mut stream = TcpStream::connect("not-an-example.com:443").await.unwrap();
///     // Must be a random number. Must be the same on the client side and the server side.
///     // DO NOT REUSE THE NUMBER GIVEN HERE, GENERATE ONE SOMEWHERE AND PUT IT IN THE SOURCE CODE
///     let tls_random_marker = 0xDEADBEEF;
///     // Same rules as tls_random_marker
///     // DO NOT USE THE SAME tls_random_marker and tls_server_data_marker
///     let tls_server_data_marker = 0xCAFEBABE;
///     tls_handshake_as_client(&mut stream, b"example.com", tls_random_marker, tls_server_data_marker).await.unwrap();
///
///     // Now you can send data over the stream and DPI will think this is a TLS connection to "example.com"
///     // But to be sure you must send data that looks like a TLS stream over the connection
/// }
/// ```
pub async fn tls_handshake_as_client(
    stream: &mut TcpStream,
    sni_hostname: &[u8],
    tls_random_marker: u32,
    tls_server_data_marker: u32
) -> io::Result<()> {
    let mut tls_random = [0u8; 32];
    rand::rng().fill(&mut tls_random);

    tls_random[TLS_RANDOM_MARKER_OFFSET..TLS_RANDOM_MARKER_OFFSET + 4]
        .copy_from_slice(&tls_random_marker.to_be_bytes());

    let hostname = ServerName::try_from(sni_hostname)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        .to_owned();
    let mut tls_client = rustls::ClientConnection::new_with_override(
        RUSTLS_CLIENT_CONFIG.clone(),
        hostname,
        tls_random
    ).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    while tls_client.is_handshaking() {
        let mut interest = if tls_client.wants_read() {
            Interest::READABLE
        } else {
            Interest::ERROR
        };
        if tls_client.wants_write() {
            interest |= Interest::WRITABLE;
        }
        // TODO: can trigger busy-waiting
        if interest == Interest::ERROR {
            continue;
        }

        let ready = stream.ready(interest).await?;
        if ready.is_readable() && tls_client.wants_read() {
            let mut buf = [0u8; 2048];
            let n = stream.read(&mut buf).await?;
            tls_client.read_tls(&mut buf[..n].as_ref())?;
            tls_client.process_new_packets().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        }
        if ready.is_writable() && tls_client.wants_write() {
            let mut buf = [0u8; 2048];
            let n = tls_client.write_tls(&mut buf.as_mut())?;
            stream.write_all(&buf[..n]).await?;
        }
    }

    // To produce application data packet
    while tls_client.wants_write() {
        let mut buf = [0u8; 2048];
        let n = tls_client.write_tls(&mut buf.as_mut())?;
        stream.write_all(&buf[..n]).await?;
    }

    // Read all application data sent by the actual server which VPN server's mimicking for
    loop {
        let packet = read_tls_packet(stream).await?;
        if packet.len() >= 5 + 4 && packet[0] == 0x17 {
            let marker = u32::from_be_bytes(packet[5..5 + 4].try_into().unwrap());
            if marker == tls_server_data_marker {
                break;
            }
        }
    }

    Ok(())
}

#[cfg(not(doctest))]
/// Sends some data over a [`TcpStream`] in a way such that DPI detects it as a usual HTTPS connection
/// to a website (server side)
///
/// This function consumes [`TcpStream`] in case that an accepted client is not a utls client and starts
/// a [`tokio::io::copy`] task in the background between the accepted client and `camouflage_server`
///
/// **To protect against replay attacks, you must negotiate tls_random_marker before calling this method
/// and never reuse it again**
///
/// Example usage:
/// ```
/// use tokio::net::{TcpListener, TcpStream};
/// use utls_rs::{tls_handshake_as_client, tls_handshake_as_server};
///
/// async {
///     let listener = TcpListener::bind("0.0.0.0:443").await.unwrap();
///     let stream = listener.accept().await.unwrap().0;
///     // Must be a random number. Must be the same on the client side and the server side.
///     // DO NOT REUSE THE NUMBER GIVEN HERE, GENERATE ONE SOMEWHERE AND PUT IT IN THE SOURCE CODE
///     let tls_random_marker = 0xDEADBEEF;
///     // Same rules as tls_random_marker
///     // DO NOT USE THE SAME tls_random_marker and tls_server_data_marker
///     let tls_server_data_marker = 0xCAFEBABE;
///     tls_handshake_as_server(stream, ("example.com", 443), tls_random_marker, tls_server_data_marker).await.unwrap();
///
///     // Now you can send data over the stream and DPI on the client side
///     // will think this is a TLS connection to "example.com"
///     // But to be sure you must send data that looks like TLS stream over the connection
/// }
/// ```
pub async fn tls_handshake_as_server<A: ToSocketAddrs + Send + 'static>(
    mut stream: TcpStream,
    camouflage_server: A,
    tls_random_marker: u32,
    tls_server_data_marker: u32
) -> io::Result<TcpStream> {
    const CAMOUFLAGE_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const CAMOUFLAGE_FORWARD_TIMEOUT: Duration = Duration::from_secs(30);
    const TLS_RANDOM_OFFSET: usize = 11;

    let camouflage_server_connection: JoinHandle<io::Result<TcpStream>> =
        tokio::task::spawn(async move {
            Ok(timeout(CAMOUFLAGE_CONNECT_TIMEOUT, TcpStream::connect(camouflage_server)).await
                .map_err(|e| io::Error::new(io::ErrorKind::TimedOut, e))??)
        });

    let client_hello = read_tls_packet(&mut stream).await?;

    let marker_offset = TLS_RANDOM_OFFSET + TLS_RANDOM_MARKER_OFFSET;
    if client_hello.len() <= marker_offset + 4 {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "Invalid Client Hello"));
    }
    let marker = u32::from_be_bytes(
        client_hello[marker_offset..marker_offset + 4]
            .try_into()
            .unwrap()
    );
    if marker != tls_random_marker {
        tokio::task::spawn(timeout(CAMOUFLAGE_FORWARD_TIMEOUT, async move {
            let mut camouflage_server_connection = camouflage_server_connection.await.unwrap()?;
            camouflage_server_connection.write_all(&client_hello).await?;
            tokio::io::copy_bidirectional(&mut camouflage_server_connection, &mut stream).await?;
            Ok::<_, io::Error>(())
        }));

        return Err(io::Error::new(io::ErrorKind::InvalidData, "Not a bypass client (invalid marker)"));
    }

    let (mut camouflage_rx, mut camouflage_tx) =
        camouflage_server_connection.await.unwrap()?.into_split();
    let (mut stream_rx, mut stream_tx) = stream.into_split();
    camouflage_tx.write_all(&client_hello).await?;
    {
        let f = async {
            loop {
                let packet = read_tls_packet(&mut stream_rx).await?;
                if packet.len() > 0 && packet[0] == 0x17 {
                    return Ok(());
                }
                camouflage_tx.write_all(&packet).await?;
            }
        };
        tokio::pin!(f);
        loop {
            tokio::select! {
                e = tokio::io::copy(&mut camouflage_rx, &mut stream_tx) => {
                    e?;
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof).into());
                },
                x = &mut f => match x {
                    Ok(_) => break,
                    Err(e) => return Err(e)
                }
            }
        }
    }
    drop((camouflage_tx, camouflage_rx));

    // Notify client that it has been recognized
    let mut tls_packet = Vec::with_capacity(1024);
    tls_packet.extend_from_slice(&[0x17, 0x03, 0x03]);
    let random_padding_len = rand::rng().random_range(0usize..600usize);
    tls_packet.extend_from_slice(
        &((random_padding_len + 4) as u16)
            .to_be_bytes()
    );
    tls_packet.extend_from_slice(&tls_server_data_marker.to_be_bytes());
    tls_packet.extend((0..random_padding_len).map(|_| rand::rng().random::<u8>()));
    stream_tx.write_all(&tls_packet).await?;

    Ok(stream_rx.reunite(stream_tx).unwrap())
}

#[cfg(test)]
mod tests {
    use std::io::Write;
    use tokio::net::TcpListener;
    use super::*;

    #[tokio::test]
    async fn test_real() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let t = tokio::task::spawn(async move {
            let l = TcpListener::bind("127.0.0.1:12345").await.unwrap();
            ready_tx.send(()).unwrap();
            let c = l.accept().await.unwrap().0;
            let mut c = tls_handshake_as_server(
                c,
                "cloudflare.com:443",
                123,
                123
            ).await.unwrap();
            let mut data = String::new();
            c.read_to_string(&mut data).await.unwrap();
            assert_eq!(data, "Hello world!");
        });
        ready_rx.await.unwrap();
        let mut c = TcpStream::connect("127.0.0.1:12345").await.unwrap();
        tls_handshake_as_client(&mut c, "cloudflare.com".as_bytes(), 123, 123).await.unwrap();
        c.write_all("Hello world!".as_bytes()).await.unwrap();
        drop(c);
        t.await.unwrap();
    }
    #[tokio::test]
    async fn test_censor() {
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let t = tokio::task::spawn(async move {
            let l = TcpListener::bind("127.0.0.1:12346").await.unwrap();
            ready_tx.send(()).unwrap();
            let c = l.accept().await.unwrap().0;
            let res = tls_handshake_as_server(
                c,
                "google.com:443",
                123,
                123
            ).await;
            assert!(matches!(res, Err(_)));
        });

        ready_rx.await.unwrap();

        let mut c = TcpStream::connect("127.0.0.1:12346").await.unwrap();

        let hostname = ServerName::try_from("google.com")
            .unwrap()
            .to_owned();
        let mut tls_client = rustls::ClientConnection::new(
            RUSTLS_CLIENT_CONFIG.clone(),
            hostname
        ).unwrap();

        tls_client.writer().write_all("GET / HTTP/1.1\r\nHost: google.com\r\n\r\n".as_bytes()).unwrap();
        loop {
            let mut interest = if tls_client.wants_read() {
                Interest::READABLE
            } else {
                Interest::ERROR
            };
            if tls_client.wants_write() {
                interest |= Interest::WRITABLE;
            }
            // TODO: can trigger busy-waiting
            if interest == Interest::ERROR {
                continue;
            }

            let ready = c.ready(interest).await.unwrap();
            if t.is_finished() {
                t.await.unwrap();
                break;
            }
            if ready.is_readable() && tls_client.wants_read() {
                let mut buf = [0u8; 2048];
                let n = c.read(&mut buf).await.unwrap();
                tls_client.read_tls(&mut buf[..n].as_ref()).unwrap();
                tls_client.process_new_packets().unwrap();
            }
            if ready.is_writable() && tls_client.wants_write() {
                let mut buf = [0u8; 2048];
                let n = tls_client.write_tls(&mut buf.as_mut()).unwrap();
                c.write_all(&buf[..n]).await.unwrap();
            }
        }
    }
}
