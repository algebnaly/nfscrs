use crate::nfs4_types::NFSTime4;

pub fn nfs4time_to_miliseconds(time: &NFSTime4) -> i64 {
    time.seconds * 1000 + time.nseconds as i64 / 1000000
}
