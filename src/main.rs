use clap::Parser;
use ishare::Identity;

#[derive(Parser, Debug)]
#[allow(dead_code)]
#[command(version, about, long_about = None)]
struct Args {
    #[arg(short, long)]
    target_id: String,

    #[arg(short, long)]
    id_client: String,

    #[arg(short, long)]
    password: String,

    #[arg(short, long)]
    cert_file: String,

    #[arg(long)]
    perm_ishare: Option<String>,

    #[arg(short, long)]
    sattelite_url: String,

    #[arg(short, long)]
    eori_sattelite: String,
}

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let identity = Identity::from_p12(&args.cert_file, &args.password, &args.id_client).unwrap();
    let token = identity.create_client_assertion(args.target_id).unwrap();

    println!("{}", token);
}
