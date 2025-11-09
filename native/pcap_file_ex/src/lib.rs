mod filter;
mod pcap;
mod pcap_writer;
mod pcapng;
mod pcapng_writer;
mod types;

use rustler::{Env, Term};

#[allow(non_local_definitions)]
fn load(env: Env, _info: Term) -> bool {
    rustler::resource!(pcap::PcapReaderResource, env)
        && rustler::resource!(pcapng::PcapNgReaderResource, env)
        && rustler::resource!(pcap_writer::PcapWriterResource, env)
        && rustler::resource!(pcapng_writer::PcapNgWriterResource, env)
}

rustler::init!("Elixir.PcapFileEx.Native", load = load);
