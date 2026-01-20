use std::borrow::Cow;
use std::fmt::Display;
use std::ops::Deref;
use std::path::{Component, Path, PathBuf};
use std::str::FromStr;

use crate::NFSCRSInnerError;
use crate::fattr4::FAttr4;
use crate::nfs4_types::Component4;

pub type AbsolutePathOwned = AbsolutePath<'static>;
pub type AbsolutePathRef<'a> = AbsolutePath<'a>;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AbsolutePath<'a>(Cow<'a, Path>); // we assume no '.' and '..' in path, 

impl<'a> AbsolutePath<'a> {
    /// Access inner `Cow<Path>` if needed
    pub fn as_cow(&self) -> &Cow<'a, Path> {
        &self.0
    }
    pub fn into_owned(self) -> AbsolutePath<'static> {
        AbsolutePath(Cow::Owned(self.0.into_owned()))
    }

    pub fn is_root(&self) -> bool {
        self.0.components().all(|c| matches!(c, Component::RootDir))
    }

    pub fn parent_absolute(&'a self) -> Option<AbsolutePath<'a>> {
        self.0.parent().map(|p| AbsolutePath(Cow::Borrowed(p)))
    }
}

impl<'a> TryFrom<&'a Path> for AbsolutePath<'a> {
    type Error = NFSCRSInnerError;

    fn try_from(value: &'a Path) -> Result<Self, Self::Error> {
        if value.is_absolute() {
            if misc::contains_current_or_parent(value) {
                Err(NFSCRSInnerError::InvalidArgument(
                    "path contains . or ..".to_owned(),
                ))
            } else {
                Ok(Self(Cow::Borrowed(value)))
            }
        } else {
            Err(NFSCRSInnerError::InvalidArgument(
                "path is not absolute".to_owned(),
            ))
        }
    }
}

impl TryFrom<PathBuf> for AbsolutePath<'static> {
    type Error = NFSCRSInnerError;

    fn try_from(value: PathBuf) -> Result<Self, Self::Error> {
        if value.is_absolute() {
            if misc::contains_current_or_parent(&value) {
                Err(NFSCRSInnerError::InvalidArgument(
                    "path contains . or ..".to_owned(),
                ))
            } else {
                Ok(Self(Cow::Owned(value)))
            }
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

impl FromStr for AbsolutePath<'static> {
    type Err = NFSCRSInnerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
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

impl<'a> AsRef<Path> for AbsolutePath<'a> {
    fn as_ref(&self) -> &Path {
        self.0.as_ref()
    }
}

impl<'a> Display for AbsolutePath<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_fmt(format_args!("{}", self.0.display()))
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

mod misc {
    use std::path::Component;
    use std::path::Path;

    pub(crate) fn contains_current_or_parent(path: &Path) -> bool {
        path.components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    }
}
