extern crate curve25519_dalek;
extern crate rand_core;
extern crate sha2;

use curve25519_dalek::constants;

use curve25519_dalek::scalar::Scalar;


use sha2::{Sha256, Digest};

use rand_core::OsRng;
use std::env;

fn main() {

    let mut message="password";
    let args: Vec = env::args().collect();
  
    if args.len() >1 { message = args[1].as_str();}

    // Base point
    let G = &constants::ED25519_BASEPOINT_POINT;

    //Private key (r)
    let r = Scalar::random(&mut OsRng);

    //Public key (rG)
    let U = r*G;


    //Create a random nonce (rt) for each proof
    let rt = Scalar::random(&mut OsRng);

    let Ut = rt*G;


    // Challenge generation
    let mut temp: [u8;32] = [0u8;32];
    let mut hasher = Sha256::new();
    hasher.update(message.as_bytes());
    hasher.update(Ut.compress().to_bytes());
    temp.copy_from_slice(hasher.finalize().as_slice());

    let c = Scalar::from_bytes_mod_order(temp);

    let rz = rt + c*r;

    println!("Message:={:}",message);

    println!("\nG={:}",hex::encode(G.compress().as_bytes()));

    println!("-- Let's pick the private key (r) -- ");
    println!("r= {:}",hex::encode(r.as_bytes()));
    println!("-- Let's generate the public key (rG) -- ");
    println!("\nU=rG= {:}",hex::encode(U.compress().as_bytes()));

    println!("\n-- Let's pick a random value (rt) -- ");
    println!("rt= {:}",hex::encode(rt.as_bytes()));

    println!("Ut=rtG= {:}",hex::encode(Ut.compress().as_bytes()));

    println!("\n-- Let's generate the challenge (c) and response (rz) -- ");
    println!("c= {:}",hex::encode(c.as_bytes()));
    println!("rz=rt+c*r {:}",hex::encode(rz.as_bytes()));

    let p1=rz*G;
    let p2=Ut+c*U;
    println!("\n-- Computing the proof -- ");
    println!("\nrz*G={:}",hex::encode(p1.compress().as_bytes()));
    println!("Ut+c*U{:}",hex::encode(p2.compress().as_bytes()));

    if (p1==p2) {
        println!("Proven!!");   
    }
    else {
        println!("Not proven");
    }

}
