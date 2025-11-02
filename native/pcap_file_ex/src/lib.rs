mod pcap;
mod pcapng;
mod types;

use rustler::{Env, Term};

fn load(env: Env, _info: Term) -> bool {
    rustler::resource!(pcap::PcapReaderResource, env);
    rustler::resource!(pcapng::PcapNgReaderResource, env);
    true
}

rustler::init!("Elixir.PcapFileEx.Native", load = load);
