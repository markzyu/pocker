// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use core::cell::RefCell;
use thiserror::Error;

/// This error type is for future proofing only. It will always implement Debug.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AsyncRuntimeError {
    #[error("Cannot enqueue more pending futures, exceeding MAX_PENDING")]
    TooManyPending,

    #[error("Unblocking more than one future in a single async step is disallowed")]
    TooManyUnblocked,
}

/// A fixed-sized lookup Map, implemented as a sorted array
#[derive(Debug)]
pub struct FixedSizedMap<K: Eq + Ord, V, const N: usize> {
    items: RefCell<[Option<(K, V)>; N]>,
    size: RefCell<usize>,
}

impl<K: Eq + Ord, V, const N: usize> FixedSizedMap<K, V, N> {
    pub fn new() -> Self {
        Self {
            items: RefCell::new([const { None }; N]),
            size: RefCell::new(0),
        }
    }

    pub fn len(&self) -> usize {
        *self.size.borrow()
    }

    /// Perform search in such a way that None shows up at the end of the sorted array
    fn _search(&self, slice: &[Option<(K, V)>], key: &K) -> Result<usize, usize> {
        slice.binary_search_by(|x| match x.as_ref() {
            None => Some(key).cmp(&None),
            Some((other_key, _)) => Some(key).cmp(&Some(other_key)),
        })
    }

    fn _move_within(
        &self,
        slice: &mut [Option<(K, V)>],
        range_from: usize,
        range_to: usize,
        new_start: usize,
    ) {
        let mut j = new_start;
        for i in range_from..range_to {
            slice.swap(i, j);
            j += 1;
        }
    }

    /// Edits an item if it exists. Otherwise, return false
    pub fn edit(&self, key: &K, edit_fn: impl FnOnce(V) -> V) -> bool {
        let mut items = self.items.borrow_mut();
        let search_result = self._search(&*items, key);
        if let Ok(index) = search_result {
            let (key2, val) = items[index].take().unwrap();
            let new_val = edit_fn(val);
            items[index] = Some((key2, new_val));
            true
        } else {
            false
        }
    }

    /// Reads an item by key
    pub fn read<T>(&self, key: &K, read_fn: impl Fn(&V) -> T) -> Option<T> {
        let items = self.items.borrow();
        let search_result = self._search(&*items, key);
        if let Ok(index) = search_result {
            let (_, val) = items[index].as_ref().unwrap();
            Some(read_fn(val))
        } else {
            None
        }
    }

    /// Reads an item by array index (for debugging)
    pub fn read_idx<T>(&self, idx: usize, read_fn: impl Fn(&(K, V)) -> T) -> Option<T> {
        let items = self.items.borrow();
        match items[idx].as_ref() {
            None => None,
            Some(val) => Some(read_fn(val)),
        }
    }

    /// Similar to slice.iter().find()
    pub fn find<T>(
        &self,
        mut find_fn: impl FnMut(&Option<(K, V)>) -> bool,
        result_fn: impl Fn(&(K, V)) -> T,
    ) -> Option<T> {
        let items = self.items.borrow();
        let end_idx = self.len();
        let Some(Some(result)) = items[..end_idx].iter().find(|x| find_fn(x)) else {
            return None;
        };
        Some(result_fn(result))
    }

    /// Returns None if the key doesn't exist
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut items = self.items.borrow_mut();
        let size = self.len();
        let search_result = self._search(&*items, key);
        if let Ok(index) = search_result {
            let (_, val) = items[index].take().unwrap();
            self._move_within(&mut *items, index + 1, size, index);
            items[size - 1] = None;
            self.size.replace(size - 1);
            Some(val)
        } else {
            None
        }
    }

    /// Returns false if key already exists
    pub fn set_default(&self, key: K, val: V) -> Result<bool, AsyncRuntimeError> {
        let mut items = self.items.borrow_mut();
        let size = self.len();
        let search_result = self._search(&*items, &key);
        match search_result {
            Err(index) => {
                if size == N {
                    return Err(AsyncRuntimeError::TooManyPending);
                }
                self._move_within(&mut *items, index, size, index + 1);
                items[index] = Some((key, val));
                self.size.replace(size + 1);
                Ok(true)
            }
            Ok(_) => Ok(false),
        }
    }
}
