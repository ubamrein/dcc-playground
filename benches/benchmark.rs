use bencher::Bencher;
use bencher::{benchmark_main, benchmark_group};
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


benchmark_group!(benches, benchmark_encoding, benchmark_decoding);
benchmark_main!(benches);