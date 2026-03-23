use std::collections::HashSet;
use std::sync::RwLock;

/// Thread-safe whitelist of client X25519 public keys.
/// When `None`, whitelisting is disabled (all valid MAC1 clients accepted).
/// When `Some(set)`, only clients whose keys are in the set are accepted.
pub struct Whitelist {
    inner: RwLock<Option<HashSet<[u8; 32]>>>,
}

impl Whitelist {
    /// Create a new whitelist. If `keys` is `Some`, whitelisting is enabled.
    pub fn new(keys: Option<&[[u8; 32]]>) -> Self {
        let set = keys.map(|k| k.iter().copied().collect());
        Self {
            inner: RwLock::new(set),
        }
    }

    /// Check if a key is allowed. Returns true if whitelisting is disabled
    /// or the key is in the whitelist.
    pub fn is_allowed(&self, key: &[u8; 32]) -> bool {
        let guard = self.inner.read().unwrap();
        match &*guard {
            None => true,
            Some(set) => set.contains(key),
        }
    }

    /// Add a key to the whitelist. Enables whitelisting if not already enabled.
    pub fn allow_key(&self, key: [u8; 32]) {
        let mut guard = self.inner.write().unwrap();
        match &mut *guard {
            Some(set) => {
                set.insert(key);
            }
            None => {
                let mut set = HashSet::new();
                set.insert(key);
                *guard = Some(set);
            }
        }
    }

    /// Remove a key from the whitelist.
    pub fn remove_key(&self, key: &[u8; 32]) {
        let mut guard = self.inner.write().unwrap();
        if let Some(set) = &mut *guard {
            set.remove(key);
        }
    }

    /// Check if a specific key is in the whitelist.
    pub fn has_key(&self, key: &[u8; 32]) -> bool {
        let guard = self.inner.read().unwrap();
        match &*guard {
            None => false,
            Some(set) => set.contains(key),
        }
    }

    /// Get a copy of all whitelisted keys.
    pub fn allowed_keys(&self) -> Vec<[u8; 32]> {
        let guard = self.inner.read().unwrap();
        match &*guard {
            None => vec![],
            Some(set) => set.iter().copied().collect(),
        }
    }

    /// Enable whitelisting with the given initial keys.
    pub fn enable(&self, keys: &[[u8; 32]]) {
        let mut guard = self.inner.write().unwrap();
        *guard = Some(keys.iter().copied().collect());
    }

    /// Disable whitelisting entirely.
    pub fn disable(&self) {
        let mut guard = self.inner.write().unwrap();
        *guard = None;
    }

    /// Check if whitelisting is currently enabled.
    pub fn is_enabled(&self) -> bool {
        self.inner.read().unwrap().is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disabled_allows_all() {
        let wl = Whitelist::new(None);
        assert!(wl.is_allowed(&[1u8; 32]));
        assert!(!wl.is_enabled());
    }

    #[test]
    fn test_enabled_blocks_unknown() {
        let key = [1u8; 32];
        let wl = Whitelist::new(Some(&[key]));
        assert!(wl.is_allowed(&key));
        assert!(!wl.is_allowed(&[2u8; 32]));
    }

    #[test]
    fn test_runtime_add_remove() {
        let wl = Whitelist::new(None);
        let key = [1u8; 32];

        wl.allow_key(key);
        assert!(wl.is_enabled());
        assert!(wl.has_key(&key));

        wl.remove_key(&key);
        assert!(!wl.has_key(&key));

        wl.disable();
        assert!(!wl.is_enabled());
        assert!(wl.is_allowed(&key)); // disabled = allow all
    }
}
