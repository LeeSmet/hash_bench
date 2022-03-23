use blake2::{
    digest::consts::{U32, U64},
    Digest,
};
use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use rand::RngCore;

trait Hasher {
    type Output;
    fn hash(self, chunks: &[u8], chunk_size: usize) -> Self::Output;
}

struct Md5hasher {
    ctx: md5::Context,
}

impl Md5hasher {
    fn new() -> Self {
        Self {
            ctx: md5::Context::new(),
        }
    }
}

impl Hasher for Md5hasher {
    type Output = [u8; 16];

    fn hash(mut self, chunks: &[u8], chunk_size: usize) -> Self::Output {
        for c in chunks.chunks(chunk_size) {
            self.ctx.consume(c);
        }

        self.ctx.compute().into()
    }
}

struct Blake2Hasher32 {
    hasher: blake2::Blake2b<U32>,
}

impl Blake2Hasher32 {
    fn new() -> Self {
        Self {
            hasher: blake2::Blake2b::default(),
        }
    }
}

impl Hasher for Blake2Hasher32 {
    type Output = [u8; 32];
    fn hash(mut self, chunks: &[u8], chunk_size: usize) -> Self::Output {
        for c in chunks.chunks(chunk_size) {
            self.hasher.update(&c);
        }
        self.hasher.finalize().into()
    }
}

struct Blake2Hasher64 {
    hasher: blake2::Blake2b<U64>,
}

impl Blake2Hasher64 {
    fn new() -> Self {
        Self {
            hasher: blake2::Blake2b::default(),
        }
    }
}

impl Hasher for Blake2Hasher64 {
    type Output = [u8; 64];
    fn hash(mut self, chunks: &[u8], chunk_size: usize) -> Self::Output {
        for c in chunks.chunks(chunk_size) {
            self.hasher.update(&c);
        }
        self.hasher.finalize().into()
    }
}

struct Blake3Hasher32 {
    hasher: blake3::Hasher,
}

impl Blake3Hasher32 {
    fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }
}

impl Hasher for Blake3Hasher32 {
    type Output = [u8; 32];
    fn hash(mut self, chunks: &[u8], chunk_size: usize) -> Self::Output {
        for c in chunks.chunks(chunk_size) {
            self.hasher.update(&c);
        }
        self.hasher.finalize().into()
    }
}

struct Blake3Hasher64 {
    hasher: blake3::Hasher,
}

impl Blake3Hasher64 {
    fn new() -> Self {
        Self {
            hasher: blake3::Hasher::new(),
        }
    }
}

impl Hasher for Blake3Hasher64 {
    type Output = [u8; 64];
    fn hash(mut self, chunks: &[u8], chunk_size: usize) -> Self::Output {
        for c in chunks.chunks(chunk_size) {
            self.hasher.update(&c);
        }
        let mut output_reader = self.hasher.finalize_xof();
        let mut output = [0; 64];
        output_reader.fill(&mut output);
        output
    }
}

struct Crc32Hasher {
    hasher: crc32fast::Hasher,
}

impl Crc32Hasher {
    fn new() -> Self {
        Self {
            hasher: crc32fast::Hasher::new(),
        }
    }
}

impl Hasher for Crc32Hasher {
    type Output = [u8; 4];
    fn hash(mut self, chunks: &[u8], chunk_size: usize) -> Self::Output {
        for c in chunks.chunks(chunk_size) {
            self.hasher.update(&c);
        }
        self.hasher.finalize().to_be_bytes()
    }
}

fn bench(c: &mut Criterion) {
    let mut bytes = vec![0; 1 << 20];
    rand::thread_rng().fill_bytes(&mut bytes);

    let mut group = c.benchmark_group("md5 hashing");
    for i in 0..16 {
        let chunk_size = 16 << i;
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_size),
            &chunk_size,
            |b, cs| {
                b.iter(|| {
                    let hasher = Md5hasher::new();
                    hasher.hash(&bytes, *cs);
                })
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("blake2 hashing (32 byte digest)");
    for i in 0..16 {
        let chunk_size = 16 << i;
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_size),
            &chunk_size,
            |b, cs| {
                b.iter(|| {
                    let hasher = Blake2Hasher32::new();
                    hasher.hash(&bytes, *cs);
                })
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("blake2 hashing (64 byte digest)");
    for i in 0..16 {
        let chunk_size = 16 << i;
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_size),
            &chunk_size,
            |b, cs| {
                b.iter(|| {
                    let hasher = Blake2Hasher64::new();
                    hasher.hash(&bytes, *cs);
                })
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("blake3 hashing (32 byte digest)");
    for i in 0..16 {
        let chunk_size = 16 << i;
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_size),
            &chunk_size,
            |b, cs| {
                b.iter(|| {
                    let hasher = Blake3Hasher32::new();
                    hasher.hash(&bytes, *cs);
                })
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("blake3 hashing (64 byte digest)");
    for i in 0..16 {
        let chunk_size = 16 << i;
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_size),
            &chunk_size,
            |b, cs| {
                b.iter(|| {
                    let hasher = Blake3Hasher64::new();
                    hasher.hash(&bytes, *cs);
                })
            },
        );
    }
    group.finish();

    let mut group = c.benchmark_group("crc32");
    for i in 0..16 {
        let chunk_size = 16 << i;
        group.throughput(Throughput::Bytes(bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::from_parameter(chunk_size),
            &chunk_size,
            |b, cs| {
                b.iter(|| {
                    let hasher = Crc32Hasher::new();
                    hasher.hash(&bytes, *cs);
                })
            },
        );
    }
    group.finish();
}

criterion_group!(benches, bench);
criterion_main!(benches);
