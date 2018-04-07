extern crate futures;
extern crate tokio_core;
extern crate trust_dns;
extern crate trust_dns_proto;
#[macro_use] extern crate failure;
#[macro_use] extern crate failure_derive;
#[macro_use] extern crate lazy_static;

use std::str::FromStr;
use std::io;

use trust_dns::client::{Client, ClientConnection, ClientFuture, ClientStreamHandle, SyncClient};
use trust_dns::udp::UdpClientConnection;
use trust_dns::tcp::TcpClientConnection;
use trust_dns::rr::{DNSClass, Name, RData, Record, RecordType};
use trust_dns::op::{Edns, Message, Query};
use trust_dns::rr::rdata::opt::{EdnsOption, EdnsCode};

use trust_dns_proto::DnsHandle;

use failure::Error;
use futures::prelude::*;
use tokio_core::reactor::{Core, Handle};

lazy_static! {
    static ref TESTING_SERVER: Name = Name::from_str("dnssec-tools.org.")
                                            .expect("Name building should never fail.");
}

/*
 3.1.1.  Supports UDP Answers

   Purpose: This tests basic DNS-over-UDP functionality to a resolver.

   Test: A DNS request is sent to the resolver under test for an A
   record for a known existing domain, such as good-a.test.example.com.

   SUCCESS: A DNS response was received that contains an A record in the
   answer section.  (The data itself does not need to be checked.)

   Note: An implementation MAY chose not to perform the rest of the
   tests if this test fails, as it is highly unlikely that the resolver
   under test will pass any of the remaining tests.

3.1.2.  Supports TCP Answers

   Purpose: This tests basic TCP functionality to a resolver.

   Test: A DNS request is sent over TCP to the resolver under test for
   an A record for a known existing domain, such as good-
   a.test.example.com.

   SUCCESS: A DNS response was received that contains an A record in the
   answer section.  (The data itself does not need to be checked.)
*/

fn support_simple_answers<CC>(client: SyncClient<CC>) -> Result<(), &'static str>
  where CC: ClientConnection,
        <CC as ClientConnection>::MessageStream: Stream<Item=Vec<u8>, Error=io::Error> + 'static
{
    client.query(&TESTING_SERVER, DNSClass::IN, RecordType::A)
          .map(|_| ())
          .map_err(|_| "query failed")
}

/*
3.1.3.  Supports EDNS0

   Purpose: Test whether a resolver properly supports the EDNS0
   extension option.

   Prerequisite: Supports UDP or TCP.

   Test: Send a request to the resolver under test for an A record for a
   known existing domain, such as good-a.test.example.com, with an EDNS0
   OPT record in the additional section.

   SUCCESS: A DNS response was received that contains an EDNS0 option
   with version number 0.

*/

fn support_edns0<CC>(conn: CC) -> Result<(), Error>
  where CC: ClientConnection,
        <CC as ClientConnection>::MessageStream: Stream<Item=Vec<u8>, Error=io::Error> + 'static
{
    
    let query = Query::query(TESTING_SERVER.clone(), RecordType::A);
    let mut edns = Edns::new();
    let v = vec![];
    edns.set_option(EdnsOption::from((EdnsCode::Zero, &v[..])));
    let mut msg = Message::new();
    msg.add_query(query);
    msg.set_edns(edns);

    let mut reactor = Core::new()?;
    let handle = &reactor.handle();
    let (stream, stream_handle) = conn.new_stream(handle).unwrap();
    let mut client_handle = ClientFuture::new(stream, stream_handle, handle, None);
    let response_future = client_handle.send(msg);
    if let Ok(msg) = reactor.run(response_future) {
        if let Some(edns) = msg.edns() {
            if edns.version() == 0 {
                Ok(())
            } else {
                Err(format_err!("Wrong EDNS option"))
            }
        } else {
            Err(format_err!("No EDNS option"))
        }
    } else {
        Err(format_err!("error in reactor"))
    }
}

fn main() {
    let address = "8.8.8.8:53".parse().unwrap();
    
    let connection = UdpClientConnection::new(address).unwrap();
    let udp_client = SyncClient::new(connection.clone());
    println!("Support UDP answers: {:?}", support_simple_answers(udp_client));

    {
        let connection = TcpClientConnection::new(address).unwrap();
        let tcp_client = SyncClient::new(connection);
        println!("Support TCP answers: {:?}", support_simple_answers(tcp_client));
    }

    println!("Support EDNS0: {:?}", support_edns0(connection));
}
