#![allow(dead_code)]
use serde::{
    Deserialize,
    de::{VariantAccess, Visitor},
};
use serde_xdr::from_bytes;

#[derive(Debug, Deserialize)]
struct ValOk {
    a: u32,
    b: u32,
}

#[derive(Debug)]
enum TestDeserialize {
    ValueOk(ValOk),
    Default,
}

struct TestDeserializeVisitor {}
impl<'de> Visitor<'de> for TestDeserializeVisitor {
    type Value = TestDeserialize;
    fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
        formatter.write_str("expecting TestDeserialize")
    }

    fn visit_enum<A>(self, data: A) -> Result<Self::Value, A::Error>
    where
        A: serde::de::EnumAccess<'de>,
    {
        let (descriminant, v): (u32, _) = data.variant()?;
        match descriminant {
            0 => {
                let val = v.newtype_variant()?;
                Ok(TestDeserialize::ValueOk(val))
            }
            _ => {
                v.unit_variant()?;
                Ok(TestDeserialize::Default)
            }
        }
    }
}

impl<'de> Deserialize<'de> for TestDeserialize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_enum(
            "TestDeserialize",
            &["ValueOk", "Default"],
            TestDeserializeVisitor {},
        )
    }
}

fn main() {
    let data: &[u8] = &[0, 0, 0, 17];
    let t_e: TestDeserialize = from_bytes(data).unwrap();
    println!("{:?}", t_e);
}
