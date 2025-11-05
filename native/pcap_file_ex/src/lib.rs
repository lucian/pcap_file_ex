mod filter;
mod pcap;
mod pcapng;
mod types;

use rustler::{Env, Term};

#[allow(non_local_definitions)]
fn load(env: Env, _info: Term) -> bool {
    rustler::resource!(pcap::PcapReaderResource, env)
        && rustler::resource!(pcapng::PcapNgReaderResource, env)
}

rustler::init!("Elixir.PcapFileEx.Native", load = load);
