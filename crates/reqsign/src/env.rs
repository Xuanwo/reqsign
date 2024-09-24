use std::collections::HashMap;
use std::fmt::Debug;
use std::path::PathBuf;

/// Permits parameterizing the home functions via the _from variants
pub trait Env: Debug + 'static {
    /// Get an environment variable.
    ///
    /// - Returns `Some(v)` if the environment variable is found and is valid utf-8.
    /// - Returns `None` if the environment variable is not found or value is invalid.
    fn var(&self, key: &str) -> Option<String>;

    /// Returns an hashmap of (variable, value) pairs of strings, for all the
    /// environment variables of the current process.
    fn vars(&self) -> HashMap<String, String>;

    /// Return the path to the users home dir, returns `None` if any error occurs.
    fn home_dir(&self) -> Option<PathBuf>;
}

/// Implements Env for the OS context, both Unix style and Windows.
#[derive(Debug, Copy, Clone)]
pub struct OsEnv;

impl Env for OsEnv {
    fn var(&self, key: &str) -> Option<String> {
        std::env::var_os(key)?.into_string().ok()
    }

    fn vars(&self) -> HashMap<String, String> {
        std::env::vars().collect()
    }

    #[cfg(any(unix, target_os = "redox"))]
    fn home_dir(&self) -> Option<PathBuf> {
        #[allow(deprecated)]
        std::env::home_dir()
    }

    #[cfg(windows)]
    fn home_dir(&self) -> Option<PathBuf> {
        windows::home_dir_inner()
    }

    #[cfg(target_arch = "wasm32")]
    fn home_dir(&self) -> Option<PathBuf> {
        None
    }
}

/// StaticEnv provides a static env environment.
///
/// This is useful for testing or for providing a fixed environment.
#[derive(Debug, Clone)]
pub struct StaticEnv {
    /// The home directory to use.
    pub home_dir: Option<PathBuf>,
    /// The environment variables to use.
    pub envs: HashMap<String, String>,
}

impl Env for StaticEnv {
    fn var(&self, key: &str) -> Option<String> {
        self.envs.get(key).cloned()
    }

    fn vars(&self) -> HashMap<String, String> {
        self.envs.clone()
    }

    fn home_dir(&self) -> Option<PathBuf> {
        self.home_dir.clone()
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use std::env;
    use std::ffi::OsString;
    use std::os::windows::ffi::OsStringExt;
    use std::path::PathBuf;
    use std::ptr;
    use std::slice;

    use windows_sys::Win32::Foundation::S_OK;
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{
        FOLDERID_Profile, SHGetKnownFolderPath, KF_FLAG_DONT_VERIFY,
    };

    pub fn home_dir_inner() -> Option<PathBuf> {
        env::var_os("USERPROFILE")
            .filter(|s| !s.is_empty())
            .map(PathBuf::from)
            .or_else(home_dir_crt)
    }

    #[cfg(not(target_vendor = "uwp"))]
    fn home_dir_crt() -> Option<PathBuf> {
        unsafe {
            let mut path = ptr::null_mut();
            match SHGetKnownFolderPath(
                &FOLDERID_Profile,
                KF_FLAG_DONT_VERIFY as u32,
                std::ptr::null_mut(),
                &mut path,
            ) {
                S_OK => {
                    let path_slice = slice::from_raw_parts(path, wcslen(path));
                    let s = OsString::from_wide(&path_slice);
                    CoTaskMemFree(path.cast());
                    Some(PathBuf::from(s))
                }
                _ => {
                    // Free any allocated memory even on failure. A null ptr is a no-op for `CoTaskMemFree`.
                    CoTaskMemFree(path.cast());
                    None
                }
            }
        }
    }

    #[cfg(target_vendor = "uwp")]
    fn home_dir_crt() -> Option<PathBuf> {
        None
    }

    extern "C" {
        fn wcslen(buf: *const u16) -> usize;
    }

    #[cfg(not(target_vendor = "uwp"))]
    #[cfg(test)]
    mod tests {
        use super::home_dir_inner;
        use std::env;
        use std::ops::Deref;
        use std::path::{Path, PathBuf};

        #[test]
        fn test_with_without() {
            let olduserprofile = env::var_os("USERPROFILE").unwrap();

            env::remove_var("HOME");
            env::remove_var("USERPROFILE");

            assert_eq!(home_dir_inner(), Some(PathBuf::from(olduserprofile)));

            let home = Path::new(r"C:\Users\foo tar baz");

            env::set_var("HOME", home.as_os_str());
            assert_ne!(home_dir_inner().as_ref().map(Deref::deref), Some(home));

            env::set_var("USERPROFILE", home.as_os_str());
            assert_eq!(home_dir_inner().as_ref().map(Deref::deref), Some(home));
        }
    }
}
