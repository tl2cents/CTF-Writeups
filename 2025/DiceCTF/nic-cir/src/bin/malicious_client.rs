use std::fs::File;
use std::io::Write;
use std::io;
use std::net::TcpStream;

use clap::Parser;
use fancy_garbling::{
    circuit::{BinaryCircuit as Circuit, CustomEvaluableCircuit, EvaluableCircuit}, twopac::semihonest::Evaluator, FancyInput, WireLabel, WireMod2
};


use scuttlebutt::{serialization::CanonicalSerialize, AbstractChannel, AesRng, Malicious, SymChannel};

use nil_circ::{
    BLOCK_SIZE, pack_block, unpack_block,
    ot::Receiver,
    malicious_ot::MaliciousReceiver,
};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    address: String,

    #[arg(long)]
    circuit: String,

    #[arg(long)]
    input: String,
}


fn handle<C: AbstractChannel>(mut channel: C, circ: &Circuit, inp: &[u8]) -> io::Result<()> {
    static WIRE_SPEC: [u16; 128] = [2; BLOCK_SIZE * 8];

    let mut magic = [0; 8];
    channel.read_bytes(&mut magic).unwrap();
    assert_eq!(b"NILCIRC\n", &magic);

    println!("{:?}", unpack_block(inp));

    let rng = AesRng::new();
    let mut ev = Evaluator::<_, _, MaliciousReceiver, WireMod2>::new(channel, rng).unwrap();
    let inp_wires = ev.encode_many(&unpack_block(inp), &WIRE_SPEC).unwrap();
    let key_wires = ev.receive_many(&WIRE_SPEC).unwrap();
    let delta = inp_wires[0].clone();
    // change inp_wires[0]
    // let mut rng2 = AesRng::new();
    // inp_wires[0] = inp_wires[0].plus(&WireMod2::rand_delta(&mut rng2, 2));
    let out= circ.custom_eval(&mut ev, &inp_wires, &key_wires, &delta).unwrap();
    println!("out: {}", out);
    // let out = &circ.eval(&mut ev, &inp_wires, &key_wires).unwrap();
  
    // all lables of ni - 1 input wires where ni is the number of input wires
    // make the input be all zero, then these are exactly the zero lables
    let inp_wires_lables0 = &inp_wires[1..]; 
    // other lables of input wires
    // make the input be all zero, then these are exactly the one lables
    let inp_wires_lables1 = inp_wires_lables0
        .iter()
        .map(|w| w.plus(&delta))
        .collect::<Vec<_>>();
    let key_wires_pair_lables = key_wires
        .iter()
        .map(|k| (k.clone(), k.plus(&delta)))
        .collect::<Vec<_>>();

    // Create or truncate output file
    let mut file = File::create("wire_labels.txt")?;
    
    // Write the delta to the file
    writeln!(file, "{}", hex::encode(delta.as_block().to_bytes()))?;

    // Write input wire labels (0)
    writeln!(file, "Input Wire Labels (0):")?;
    for label in inp_wires_lables0.iter() {
        writeln!(file, "{}", hex::encode(label.as_block().to_bytes()))?;
    }
    // Write input wire labels (1)
    writeln!(file, "\nInput Wire Labels (1):")?;
    for label in inp_wires_lables1.iter() {
        writeln!(file, "{}", hex::encode(label.as_block().to_bytes()))?;
    }
    // Write key wire labels
    writeln!(file, "\nKey Wire Labels:")?;
    for (label0, label1) in key_wires_pair_lables.iter() {
        writeln!(file, "{} {}", hex::encode(label0.as_block().to_bytes()), hex::encode(label1.as_block().to_bytes()))?;
    }

    // println!("encrypted input: {}", hex::encode(out));

    Ok(())
}

fn main() -> io::Result<()> {
    let args = Args::parse();

    let file = File::open(args.circuit)?;
    let reader = io::BufReader::new(file);
    let circ = Circuit::parse(reader).expect("invalid circuit file");

    let inp = &hex::decode(args.input).expect("input must be hex");
    assert!(inp.len() == 16, "input must be 16 bytes");

    let stream = TcpStream::connect(args.address)?;
    let channel = SymChannel::new(stream);
    handle(channel, &circ, inp)?;

    Ok(())
}
