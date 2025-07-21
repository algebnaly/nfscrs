use std::borrow::Cow;
use std::ops::Deref;
use std::path::{Path, PathBuf};

use crate::NFSCRSInnerError;
use crate::nfs4types::Component4;
use crate::nfsv4ops::FAttr4;

#[derive(Debug, Clone)]
pub struct AbsolutePath<'a>(Cow<'a, Path>);

impl<'a> AbsolutePath<'a> {
    /// Access inner `Cow<Path>` if needed
    pub fn as_cow(&self) -> &Cow<'a, Path> {
        &self.0
    }
    pub fn into_owned(self) -> AbsolutePath<'static> {
        AbsolutePath(Cow::Owned(self.0.into_owned()))
    }
}

impl<'a> TryFrom<&'a Path> for AbsolutePath<'a> {
    type Error = NFSCRSInnerError;

    fn try_from(value: &'a Path) -> Result<Self, Self::Error> {
        if value.is_absolute() {
            Ok(Self(Cow::Borrowed(value)))
        } else {
            Err(NFSCRSInnerError::InvalidArgument(
                "path is not absolute".to_owned(),
            ))
        }
    }
}

impl<'a> TryFrom<PathBuf> for AbsolutePath<'a> {
    type Error = NFSCRSInnerError;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        if value.is_absolute() {
            Ok(Self(Cow::Owned(value)))
        } else {
            Err(NFSCRSInnerError::InvalidArgument(
                "path is not absolute".to_owned(),
            ))
        }
    }
}

impl<'a> TryFrom<&'a str> for AbsolutePath<'a> {
    type Error = NFSCRSInnerError;

    fn try_from(value: &'a str) -> Result<Self, Self::Error> {
        let path = Path::new(value);
        Self::try_from(path)
    }
}

impl TryFrom<String> for AbsolutePath<'static> {
    type Error = NFSCRSInnerError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        let path = PathBuf::from(value);
        Self::try_from(path)
    }
}

impl<'a> Deref for AbsolutePath<'a> {
    type Target = Path;

    fn deref(&self) -> &Self::Target {
        self.0.as_ref()
    }
}

#[derive(Debug, Clone)]
pub struct DirEntry {
    pub name: Component4,
    pub attrs: FAttr4,
}

impl DirEntry {
    pub fn new(name: Component4, attrs: FAttr4) -> Self {
        Self { name, attrs }
    }
}
