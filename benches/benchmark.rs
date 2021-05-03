use bencher::Bencher;
use bencher::{benchmark_main, benchmark_group};
use rust_dgc::base45::ALPHABET;
fn benchmark_encoding(bench: &mut Bencher) {
    bench.iter(|| {
        let sample_3 = "base-45";
        rust_dgc::base45::encode(sample_3.as_bytes())
    })
}
fn benchmark_decoding(bench: &mut Bencher) {
    bench.iter(|| {
        let sample_3 = "UJCLQE7W581";
       rust_dgc::base45::decode(sample_3)
    })
}

fn benchmark_large_encoding(bench: &mut Bencher) {
    let random_bytes: Vec<u8> = (0..1_000_000).map(|_| { rand::random::<u8>() }).collect();
    bench.iter(|| {
        rust_dgc::base45::encode(&random_bytes)
    })
}

fn benchmark_large_decoding(bench: &mut Bencher) {
     use rand::Rng;
   
    let random_bytes: Vec<u8> = (0..1_500_000).map(|_| { 
        let mut rng = rand::thread_rng();
        let idx : usize = rng.gen_range(0..ALPHABET.len()); 
        ALPHABET[idx] as u8
    }).collect();
    let decoded = String::from_utf8(random_bytes).unwrap();
    bench.iter(|| {
        rust_dgc::base45::decode(&decoded)
    })
}

benchmark_group!(benches, benchmark_encoding, benchmark_decoding, benchmark_large_encoding, benchmark_large_decoding);
benchmark_main!(benches);