#![feature(test)]
#![feature(or_patterns)]

use ahash;
use anyhow::{Error, Result};
use core::iter::IntoIterator;
use criterion::{
    black_box, criterion_group, AxisScale, BenchmarkId, Criterion, PlotConfiguration, Throughput,
};
use csv;
use fxhash;
use regex::Regex;
use resiter::{and_then::*, filter::*, while_ok::*};
use serde::ser::Serialize;
use std::{
    any::type_name,
    cmp::min,
    collections::hash_map::RandomState,
    collections::{BTreeMap, BTreeSet},
    default::Default,
    fs,
    hash::{BuildHasher, Hasher},
    io::Write,
    str::FromStr,
};
use twox_hash;
use walkdir::WalkDir;
use xxhrs::{
    EntropyPool, RandomStateXXH32, RandomStateXXH3_128, RandomStateXXH3_64, RandomStateXXH64,
    XXH3_128Hmac, XXH3_64Hmac, XXH32, XXH3_128, XXH3_64, XXH64,
};

const DATA: &[u8] = include_bytes!("../src/fixtures/data");
const SECRET: &[u8] = include_bytes!("../src/fixtures/secret");
const ENTROPY: EntropyPool = EntropyPool {
    entropy: *include_bytes!("../src/fixtures/secret_entropy"),
};

pub fn type_basename<T>() -> &'static str {
    type_name::<T>().rsplit("::").next().unwrap()
}

fn bench_entropy_derivation(c: &mut Criterion) {
    let mut g = c.benchmark_group("entropy_derivation");
    g.sample_size(1000);
    g.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));

    macro_rules! b {
        ($name:expr, $fn:expr) => {{
            g.bench_function($name, |b| {
                b.iter(|| $fn());
            });
        }};
    };

    b!("randomize", || EntropyPool::randomize());
    b!("with_seed", || EntropyPool::with_seed(black_box(42)));
    b!("with_key", || EntropyPool::with_key(black_box(SECRET)));
    b!("with_key_xxh3_hkfd", || EntropyPool::with_key_xxh3_hkdf(
        black_box(SECRET)
    ));
    b!("with_key_shake128", || EntropyPool::with_key_shake128(
        black_box(SECRET)
    ));
}

fn bench_hash(c: &mut Criterion) {
    let mut g = c.benchmark_group("hashes");

    g.sample_size(1000);
    g.plot_config(PlotConfiguration::default().summary_scale(AxisScale::Logarithmic));

    let mut sz: usize = 0;
    loop {
        macro_rules! b {
            ($name:expr, $fn:expr) => {{
                let id = BenchmarkId::new($name, sz);
                g.throughput(Throughput::Bytes(sz as u64));
                g.bench_with_input(id, &DATA[0..sz], |b, d| {
                    b.iter(|| $fn(d));
                });
            }};
        };

        macro_rules! b_streaming {
            ($name:expr, $fn:expr) => {{
                b!($name, |d| {
                    let mut h = $fn();
                    h.write(d);
                    h.finish()
                });
            }};
        };

        macro_rules! b_buildhash {
            ($name:expr, $t:ty) => {{
                let builder = <$t>::default();
                b_streaming!($name, || black_box(&builder).build_hasher())
            }};
        };

        macro_rules! b_xxhash {
            ($t:ty) => {{
                let n = type_basename::<$t>();
                b!(format!("{}::hash", n), |d| <$t>::hash(d));
                b!(format!("{}::hash_with_seed", n), |d| <$t>::hash_with_seed(
                    black_box(12345),
                    d
                ));
                b_streaming!(format!("{}::new", n), || <$t>::new());
                b_streaming!(format!("{}::with_seed", n), || <$t>::with_seed(black_box(
                    12345
                )));
            }};
        };

        macro_rules! b_xxh3 {
            ($t:ty) => {{
                let n = type_basename::<$t>();
                b!(format!("{}::hash", n), |d| <$t>::hash(d));
                b!(format!("{}::hash_with_seed", n), |d| <$t>::hash_with_seed(
                    black_box(9055972853411395268),
                    d
                ));
                b!(format!("{}::hash_with_entropy", n), |d| {
                    <$t>::hash_with_entropy(black_box(&ENTROPY), d)
                });
                b!(format!("{}::hash_with_entropy_buffer", n), |d| unsafe {
                    <$t>::hash_with_entropy_buffer(black_box(&ENTROPY.entropy), d)
                });

                b_streaming!(format!("{}::new", n), || <$t>::new());
                b_streaming!(format!("{}::with_seed", n), || <$t>::with_seed(black_box(
                    9055972853411395268
                ),));
                b_streaming!(format!("{}::with_entropy", n), || <$t>::with_entropy(
                    black_box(&ENTROPY)
                ));
                b_streaming!(format!("{}::with_entropy_buffer", n), || unsafe {
                    <$t>::with_entropy_buffer(black_box(&ENTROPY.entropy))
                });
            }};
        };

        b_xxhash!(XXH32);
        b_xxhash!(XXH64);

        b_xxh3!(XXH3_64);
        b_xxh3!(XXH3_128);

        b_xxhash!(XXH3_64Hmac);
        b_xxhash!(XXH3_128Hmac);

        b_buildhash!("xxhrs::RandomStateXXH32", RandomStateXXH32);
        b_buildhash!("xxhrs::RandomStateXXH64", RandomStateXXH64);

        b_buildhash!("xxhrs::RandomStateXXH3_64", RandomStateXXH3_64);
        b_buildhash!("xxhrs::RandomStateXXH3_128", RandomStateXXH3_128);

        b_buildhash!("RandomState", RandomState);
        b_buildhash!(
            "twox_hash::RandomXxHashBuilder32",
            twox_hash::RandomXxHashBuilder32
        );
        b_buildhash!(
            "twox_hash::RandomXxHashBuilder64",
            twox_hash::RandomXxHashBuilder64
        );
        b_buildhash!("fxhash::FxBuildHasher", fxhash::FxBuildHasher);
        b_buildhash!("ahash::RandomState", ahash::RandomState);

        // Benchmark again with more data
        if sz == 0 {
            sz = 1;
        } else if sz < DATA.len() {
            sz = min(sz * 2, DATA.len());
        } else {
            break;
        }
    }
}

criterion_group!(benches, bench_entropy_derivation, bench_hash);

// Benchmark output

pub trait OptOkExt<T> {
    fn ok(self) -> Result<T>;
}

impl<T> OptOkExt<T> for Option<T> {
    fn ok(self) -> Result<T> {
        match self {
            Some(v) => Ok(v),
            None => Err(Error::msg("Empty value in optional!")),
        }
    }
}

fn parse_unit_value(value: &str, unit: &str) -> Result<f64> {
    let unit_factor = match unit {
        "as" => 1e-9,
        "fs" => 1e-6,
        "ps" => 1e-3,
        "ns" => 1e+0,
        "us" => 1e+3,
        "µs" => 1e+3,
        "ms" => 1e+6,
        "s" => 1e9,
        "m" => 1e9 * 60.0,
        "h" => 1e9 * 60.0 * 60.0,
        _ => Err(Error::msg(format!("No such unit `{}`!", unit)))?,
    };

    Ok(f64::from_str(value)? * unit_factor)
}

fn load_samples(path: &str) -> Result<(String, u64, f64)> {
    let mut values = csv::ReaderBuilder::new()
        .has_headers(false)
        .from_path(path)?;
    let mut rec = csv::StringRecord::new();

    assert!(values.read_record(&mut rec)?, "CSV is missing it's header?");
    let c_fn = rec.iter().position(|v| v == "function").ok()?;
    let c_param = rec.iter().position(|v| v == "value").ok()?;
    let c_meas = rec.iter().position(|v| v == "sample_measured_value").ok()?;
    let c_unit = rec.iter().position(|v| v == "unit").ok()?;
    let c_ctr = rec.iter().position(|v| v == "iteration_count").ok()?;

    assert!(values.read_record(&mut rec)?, "Empty csv?");
    let v_fn = String::from(rec.get(c_fn).ok()?);
    let v_val = u64::from_str(rec.get(c_param).ok()?)?;

    assert!(!values.is_done()); // CSV is empty

    // seek to the last record
    while values.is_done() {
        assert!(values.read_record(&mut rec)?);
    }

    let v_meas = parse_unit_value(rec.get(c_meas).ok()?, rec.get(c_unit).ok()?)?;
    let v_ctr = u64::from_str(rec.get(c_ctr).ok()?)? as f64;

    Ok((v_fn, v_val, v_meas / v_ctr))
}

#[derive(Debug)]
enum JsonStackFrame {
    Object(bool),
    Array(bool),
    Key,
}

struct JsonSerializer<W>
where
    W: Write,
{
    stack: Vec<JsonStackFrame>,
    w: W,
}

impl<W> JsonSerializer<W>
where
    W: Write,
{
    fn new(w: W) -> JsonSerializer<W> {
        JsonSerializer {
            stack: Default::default(),
            w,
        }
    }

    fn raw_serialize<T>(&mut self, v: T) -> Result<&mut JsonSerializer<W>>
    where
        T: Serialize,
    {
        v.serialize(&mut serde_json::Serializer::new(&mut self.w))?;
        Ok(self)
    }

    fn raw_token(&mut self) -> Result<&mut JsonSerializer<W>> {
        match self.stack.last_mut() {
            None => {
                self.w.write_all(b"\n")?;
            }
            Some(JsonStackFrame::Object(true) | JsonStackFrame::Array(true)) => {
                self.w.write_all(b",")?;
            }
            Some(JsonStackFrame::Object(ref mut x) | JsonStackFrame::Array(ref mut x)) => {
                *x = true;
            }
            Some(JsonStackFrame::Key) => {
                self.w.write_all(b":")?;
                self.stack.pop();
            }
        };
        Ok(self)
    }

    fn raw_value(&mut self) -> Result<&mut JsonSerializer<W>> {
        assert!(!matches!(
            self.stack.last(),
            Some(JsonStackFrame::Object(_))
        ));
        self.raw_token()
    }

    fn object(&mut self) -> Result<&mut JsonSerializer<W>> {
        self.raw_value()?;
        self.w.write_all(b"{")?;
        self.stack.push(JsonStackFrame::Object(false));
        Ok(self)
    }

    fn array(&mut self) -> Result<&mut JsonSerializer<W>> {
        self.raw_value()?;
        self.w.write_all(b"[")?;
        self.stack.push(JsonStackFrame::Array(false));
        Ok(self)
    }

    fn end(&mut self) -> Result<&mut JsonSerializer<W>> {
        let what = self.stack.pop().unwrap();
        assert!(matches!(what, JsonStackFrame::Array(_)|JsonStackFrame::Object(_)));
        self.w.write_all(match what {
            JsonStackFrame::Object(_) => b"}",
            JsonStackFrame::Array(_) => b"]",
            _ => b"",
        })?;
        Ok(self)
    }

    fn key(&mut self, k: &str) -> Result<&mut JsonSerializer<W>> {
        assert!(matches!(self.stack.last(), Some(JsonStackFrame::Object(_))));
        self.raw_token()?.raw_serialize(k)?;
        self.stack.push(JsonStackFrame::Key);
        Ok(self)
    }

    fn value<T>(&mut self, v: T) -> Result<&mut JsonSerializer<W>>
    where
        T: Serialize,
    {
        self.raw_value()?.raw_serialize(v)
    }
}

impl<W> Drop for JsonSerializer<W>
where
    W: Write,
{
    fn drop(&mut self) {
        while self.stack.len() > 0 {
            self.end().unwrap();
        }
    }
}

fn gen_interactive_chart(group: &str) -> Result<()> {
    // Load samples from
    let exp = Regex::new(&format!(r"criterion/{}/\w+/\d+/new/raw.csv$", group))?;
    let samples = WalkDir::new("target/criterion")
        .into_iter()
        .map(|p| p?.path().to_str().map(String::from).ok())
        .filter_ok(|p| exp.is_match(&p))
        .and_then_ok(|p| load_samples(&p));

    // Collect test results
    let mut test_results = BTreeMap::<String, BTreeMap<u64, f64>>::new();
    let mut test_params = BTreeSet::<u64>::new();
    samples.while_ok(|(vfn, vparam, vmeas)| {
        test_results.entry(vfn).or_default().insert(vparam, vmeas);
        test_params.insert(vparam);
    })?;

    // Write to output file
    let mut j = JsonSerializer::new(fs::File::create(format!(
        "target/criterion/{}/report/chart_data.js",
        group
    ))?);

    j.w.write_all(b"window.chart_data = ")?;

    // Generate JSON
    j.object()?; // root

    j.key("chart")?
        .object()?
        .key("type")?
        .value("line")?
        .end()?;

    j.key("title")?
        .object()?
        .key("text")?
        .value("Hashes Benchmark")?
        .end()?;

    j.key("xaxis")?.object()?;
    j.key("type")?.value("category")?;
    j.key("title")?
        .object()?
        .key("text")?
        .value("Data Size (byte)?")?
        .end()?;
    j.key("categories")?.array()?;
    for p in test_params {
        j.value(p)?;
    }
    j.end()?.end()?;

    j.key("yaxis")?.object()?;
    j.key("logarithmic")?.value(true)?;
    j.key("title")?
        .object()?
        .key("text")?
        .value("Time (ns)?")?
        .end()?;
    j.end()?;

    j.key("series")?.array()?;
    for (name, samples) in test_results {
        j.object()?; // C
        j.key("name")?.value(name)?;

        j.key("data")?.array()?;
        for (_, v) in samples {
            j.value(v)?;
        }
        j.end()?;

        j.end()?;
    }
    j.end()?.end()?;

    j.w.write_all(b";")?;

    Ok(())
}

fn main() -> Result<()> {
    // Run benchmarks
    benches();
    Criterion::default().configure_from_args().final_summary();

    // Analyze
    gen_interactive_chart("entropy_derivation")?;
    gen_interactive_chart("hashes")?;

    Ok(())
}
