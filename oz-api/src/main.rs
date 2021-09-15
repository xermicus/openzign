use std::path::PathBuf;
use structopt::StructOpt;

mod server;

#[derive(StructOpt, Debug)]
#[structopt(name = "oz-api")]
pub struct Opt {
    #[structopt(
        short,
        long,
        help = "Webserver bind string",
        default_value = "0.0.0.0:8000"
    )]
    bind: String,

    #[structopt(
        short = "x",
        long,
        parse(from_os_str),
        help = "Directory in which the search index is stored"
    )]
    index_dir: PathBuf,
}

#[async_std::main]
async fn main() -> tide::Result<()> {
    let opt = Opt::from_args();
    server::start(opt).await
}
