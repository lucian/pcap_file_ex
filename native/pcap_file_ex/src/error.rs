use pcap_file::PcapError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum NifError {
    #[error("PCAP error: {0}")]
    PcapError(#[from] PcapError),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),
}

impl From<NifError> for rustler::Error {
    fn from(err: NifError) -> Self {
        rustler::Error::Term(Box::new(err.to_string()))
    }
}

pub type NifResult<T> = Result<T, NifError>;
