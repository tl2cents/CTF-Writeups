//! modified version of https://github.com/GaloisInc/swanky/blob/dev/ocelot/src/ot/chou_orlandi.rs
//! you should diff it

//! Implementation of the Chou-Orlandi oblivious transfer protocol (cf.
//! <https://eprint.iacr.org/2015/267>).
//!
//! This implementation uses the Ristretto prime order elliptic curve group from
//! the `curve25519-dalek` library and works over blocks rather than arbitrary
//! length messages.
//!
//! This version fixes a bug in the current ePrint write-up
//! (<https://eprint.iacr.org/2015/267/20180529:135402>, Page 4): if the value
//! `x^i` produced by the receiver is not randomized, all the random-OTs
//! produced by the protocol will be the same. We fix this by hashing in `i`
//! during the key derivation phase.

use ocelot::{
    Error,
    ot::{Receiver as OtReceiver, Sender as OtSender},
};
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_TABLE,
    ristretto::{RistrettoBasepointTable, RistrettoPoint},
    scalar::Scalar,
};
use rand::{CryptoRng, Rng};
use scuttlebutt::{AbstractChannel, Block, Malicious, SemiHonest};

fn hash_pt(tweak: u128, pt: &RistrettoPoint) -> Block {
    let h = blake3::keyed_hash(pt.compress().as_bytes(), &tweak.to_le_bytes());
    Block::from(<[u8; 16]>::try_from(&h.as_bytes()[0..16]).unwrap())
}

/// Oblivious transfer sender.
pub struct Sender {
    y: Scalar,
    s: RistrettoPoint,
    counter: u128,
}

impl OtSender for Sender {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        mut rng: &mut RNG,
    ) -> Result<Self, Error> {
        let y = Scalar::random(&mut rng);
        let s = &y * RISTRETTO_BASEPOINT_TABLE;
        println!("OT secret key inited: {:?}", y);
        channel.write_pt(&s)?;
        channel.flush()?;
        Ok(Self { y, s, counter: 0 })
    }

    fn send<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[(Block, Block)],
        _: &mut RNG,
    ) -> Result<(), Error> {
        println!("Entering OT with {} inputs", inputs.len());
        println!("Current counter: {}", self.counter);
        let ys = self.y * self.s;
        let ks = (0..inputs.len())
            .map(|i| {
                let r = channel.read_pt()?;
                let yr = self.y * r;
                let k0 = hash_pt(self.counter + i as u128, &yr);
                let k1 = hash_pt(self.counter + i as u128, &(ys - yr));
                Ok((k0, k1))
            })
            .collect::<Result<Vec<(Block, Block)>, Error>>()?;
        self.counter += inputs.len() as u128;
        for (input, k) in inputs.iter().zip(ks.into_iter()) {
            let c0 = k.0 ^ input.0;
            let c1 = k.1 ^ input.1;
            channel.write_block(&c0)?;
            channel.write_block(&c1)?;
        }
        channel.flush()?;
        Ok(())
    }
}

impl std::fmt::Display for Sender {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Chou-Orlandi Sender")
    }
}

/// Oblivious transfer MaliciousReceiver.
// This receiver will first find Delta value in the first OT
// Then in the remaining OTs, it will run as an honest receiver
// In this case, the returned values are [delta, label1, label2, ...]
pub struct MaliciousReceiver {
    s: RistrettoBasepointTable,
    counter: u128,
}

impl OtReceiver for MaliciousReceiver {
    type Msg = Block;

    fn init<C: AbstractChannel, RNG: CryptoRng + Rng>(
        channel: &mut C,
        _: &mut RNG,
    ) -> Result<Self, Error> {
        let s = channel.read_pt()?;
        let s = RistrettoBasepointTable::create(&s);
        Ok(Self { s, counter: 0 })
    }
    
    // In this case, the returned values are [delta, label1, label2, ...]
    fn receive<C: AbstractChannel, RNG: CryptoRng + Rng>(
        &mut self,
        channel: &mut C,
        inputs: &[bool],
        mut rng: &mut RNG,
    ) -> Result<Vec<Block>, Error> {
        let ks = inputs
            .iter()
            .enumerate()
            .map(|(i, b)| {
                let x = Scalar::random(&mut rng);
                if i == 0 {
                    // First OT, find delta, r = 1/2 s
                    let r = &Scalar::invert(&Scalar::from(2 as u128)) * &self.s;
                    channel.write_pt(&r)?;
                }
                else{
                    let r = if *b {
                        &Scalar::ONE * &self.s - &x * RISTRETTO_BASEPOINT_TABLE
                    } else {
                        &x * RISTRETTO_BASEPOINT_TABLE
                    };
                    channel.write_pt(&r)?;
                }
                Ok(hash_pt(self.counter + i as u128, &(&x * &self.s)))
            })
            .collect::<Result<Vec<Block>, Error>>()?;
        channel.flush()?;
        self.counter += inputs.len() as u128;
        inputs
            .iter()
            .enumerate()
            .zip(ks.into_iter())
            .map(|((i,b), k)| {
                let c0 = channel.read_block()?;
                let c1 = channel.read_block()?;
                if i == 0 {
                    // First OT, find delta
                    let delta = c1 ^ c0;
                    return Ok(delta);
                }
                let c = k ^ if *b { c1 } else { c0 };
                // c
                Ok(c)
            })
            .collect()
    }
}

impl std::fmt::Display for MaliciousReceiver {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Chou-Orlandi Receiver")
    }
}

impl SemiHonest for Sender {}
impl Malicious for Sender {}
impl SemiHonest for MaliciousReceiver {}
impl Malicious for MaliciousReceiver {}
