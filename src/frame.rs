use std::io;

use quinn::{RecvStream, SendStream};
use serde::{Serialize, de::DeserializeOwned};

use crate::legacy_transport::frame;

/// Receives a message as a stream.
///
/// # Errors
///
/// Returns an error if receiving the message failed.
pub async fn recv_msg<T>(recv: &mut RecvStream) -> io::Result<T>
where
    T: DeserializeOwned,
{
    let mut buf = Vec::new();
    frame::recv(recv, &mut buf).await
}

/// Sends a message as a stream.
///
/// # Errors
///
/// Return an error if sending the message failed.
pub async fn send_msg<T>(send: &mut SendStream, msg: T) -> io::Result<()>
where
    T: Serialize,
{
    let mut buf = Vec::new();
    frame::send(send, &mut buf, msg).await
}

#[cfg(test)]
mod tests {

    #[tokio::test]
    async fn send_and_recv() {
        use serde::{Deserialize, Serialize};

        use crate::test::{TOKEN, channel};

        #[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
        struct Msg {
            string: String,
            integer: i32,
            floating_point: f32,
        }

        let _lock = TOKEN.lock().await;
        let mut channel = channel().await;

        let msg_one = Msg {
            string: "hello".to_string(),
            integer: 10,
            floating_point: 10.0,
        };

        super::send_msg(&mut channel.server.send, msg_one.clone())
            .await
            .unwrap();
        let received = super::recv_msg::<Msg>(&mut channel.client.recv)
            .await
            .unwrap();
        assert_eq!(received, msg_one);

        let msg_two = Msg {
            string: "world".to_string(),
            integer: 20,
            floating_point: 20.0,
        };

        super::send_msg(&mut channel.server.send, msg_two.clone())
            .await
            .unwrap();
        let received = super::recv_msg::<Msg>(&mut channel.client.recv)
            .await
            .unwrap();
        assert_eq!(received, msg_two);
    }
}
