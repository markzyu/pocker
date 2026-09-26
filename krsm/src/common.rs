// SPDX-License-Identifier: MIT OR GPL-3.0-or-later
use core::cell::RefCell;
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AsyncRuntimeError {
    #[error("Cannot enqueue more pending futures, exceeding MAX_PENDING")]
    TooManyPending,
}

/// This is the "move" equivalent of slice::copy_within
pub fn _move_within<T>(slice: &mut [T], range_from: usize, range_to: usize, new_start: usize) {
    assert!(range_to >= range_from);
    let new_end = new_start + range_to - range_from;
    if new_start < range_from {
        let mut j = new_start;
        for i in range_from..range_to {
            slice.swap(i, j);
            j += 1;
        }
    } else if new_start > range_from {
        let mut j = new_end - 1;
        for i in (range_from..range_to).rev() {
            slice.swap(i, j);
            j -= 1;
        }
    }
}

/// A no_std lookup Map, implemented as a sorted array.
///
/// It's not very fast. Most operations would take `O(N)` time. But `edit()`
/// and `read()` are slightly faster, at `O(log N)`
///
/// This was used as an internal data structure. But please feel free to
/// reuse it for any other single-threaded purposes.
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
    ///
    /// The array sorting order is:
    /// 1. `None` shows up at the end.
    /// 2. `Some(val)` shows up in ascending order of val
    fn _search(&self, slice: &[Option<(K, V)>], key: &K) -> Result<usize, usize> {
        slice.binary_search_by(|x| {
            let Some(x) = x else {
                return core::cmp::Ordering::Greater;
            };
            x.0.cmp(key)
        })
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
    #[allow(dead_code)]
    pub(crate) fn read_idx<T>(&self, idx: usize, read_fn: impl Fn(&(K, V)) -> T) -> Option<T> {
        let items = self.items.borrow();
        match items[idx].as_ref() {
            None => None,
            Some(val) => Some(read_fn(val)),
        }
    }

    /// Similar to [Iterator::find]
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

    /// Basically: `self.keys = intersect(self.keys, other.keys);`
    pub fn inner_join_keys<U>(&self, other: &FixedSizedMap<K, U, N>) {
        let mut result: [Option<(K, V)>; N] = [const { None }; N];
        let mut our_items = self.items.borrow_mut();
        let our_len = self.len();
        let other_items = other.items.borrow();
        let other_len = other.len();

        let mut i_write = 0;
        for i in 0..other_len {
            let (key, _) = other_items[i].as_ref().unwrap();
            let our_idx = self._search(&*our_items, key);
            if let Ok(j) = our_idx {
                let (key2, val) = our_items[j].take().unwrap();
                result[i_write] = Some((key2, val));
                i_write += 1;
            }
        }

        self.size.replace(i_write);
        for i in 0..i_write {
            our_items[i].replace(result[i].take().unwrap());
        }
        for i in i_write..our_len {
            our_items[i] = None;
        }
    }

    /// Edit every entry in this map.
    ///
    /// `edit_fn` can return true to stop the iteration.
    pub fn map_edit(&self, mut edit_fn: impl FnMut(&mut (K, V)) -> bool) {
        let mut items = self.items.borrow_mut();
        let end_idx = self.len();
        for i in 0..end_idx {
            let item = items[i].as_mut().unwrap();
            if edit_fn(item) {
                break;
            }
        }
    }

    /// Edit every entry in this map, in batches.
    ///
    /// `edit_fn` can return true to stop the iteration.
    pub fn map_edit_batches(
        &self,
        batch_size: usize,
        mut edit_fn: impl FnMut(&mut [Option<(K, V)>]) -> bool,
    ) {
        let end_idx = self.len();
        let mut items = self.items.borrow_mut();
        let slice = &mut items[0..end_idx];
        for chunk in slice.chunks_mut(batch_size) {
            if edit_fn(chunk) {
                break;
            }
        }
    }

    /// Returns None if the key doesn't exist
    pub fn remove(&self, key: &K) -> Option<V> {
        let mut items = self.items.borrow_mut();
        let size = self.len();
        let search_result = self._search(&*items, key);
        if let Ok(index) = search_result {
            let (_, val) = items[index].take().unwrap();
            _move_within(&mut *items, index + 1, size, index);
            items[size - 1] = None;
            self.size.replace(size - 1);
            Some(val)
        } else {
            None
        }
    }

    /// Returns false if the key already exists
    pub fn set_default(&self, key: K, val: V) -> Result<bool, AsyncRuntimeError> {
        let mut items = self.items.borrow_mut();
        let size = self.len();
        let search_result = self._search(&*items, &key);
        match search_result {
            Err(index) => {
                if size == N {
                    return Err(AsyncRuntimeError::TooManyPending);
                }
                _move_within(&mut *items, index, size, index + 1);
                items[index] = Some((key, val));
                self.size.replace(size + 1);
                Ok(true)
            }
            Ok(_) => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{FixedSizedMap, common::_move_within};

    #[test]
    fn test_move_within_shift_to_left() {
        let mut numbers = [0, 1, 2, 3, 4, 5, 6];
        _move_within(&mut numbers, 2, 6, 0);
        assert_eq!(numbers, [2, 3, 4, 5, 0, 1, 6]);
    }

    #[test]
    fn test_move_within_shift_to_right() {
        let mut numbers = [0, 1, 2, 3, 4, 5, 6];
        _move_within(&mut numbers, 1, 5, 2);
        assert_eq!(numbers, [0, 5, 1, 2, 3, 4, 6]);
    }

    #[test]
    fn test_fixed_sized_map() {
        let map: FixedSizedMap<isize, usize, 5> = FixedSizedMap::new();
        assert!(map.set_default(1, 100).unwrap());
        assert!(map.set_default(2, 200).unwrap());
        assert!(map.set_default(-5, 300).unwrap());
        assert!(!map.set_default(1, 400).unwrap());
        assert_eq!(map.len(), 3);

        assert!(map.edit(&-5, |x| x + 1));
        assert_eq!(map.remove(&2), Some(200));
        assert_eq!(map.len(), 2);

        assert_eq!(map.read(&100, |x| *x), None);
        assert_eq!(map.read(&1, |x| *x), Some(100));
        assert_eq!(map.read(&2, |x| *x), None);
        assert_eq!(map.read(&-5, |x| *x), Some(301));

        map.map_edit(|(k, v)| {
            *k -= 100;
            *v += 1;
            false
        });
        assert_eq!(map.len(), 2);
        assert_eq!(map.read_idx(0, |x| *x), Some((-105, 302)));
        assert_eq!(map.read_idx(1, |x| *x), Some((-99, 101)));
        assert_eq!(map.read_idx(2, |x| *x), None);
    }

    #[test]
    fn test_fixed_sized_map_edit_batches() {
        let map: FixedSizedMap<isize, usize, 5> = FixedSizedMap::new();
        assert!(map.set_default(5, 7).unwrap());
        assert!(map.set_default(4, 8).unwrap());
        assert!(map.set_default(-3, 9).unwrap());

        map.map_edit_batches(2, |batch| {
            for item in batch {
                let Some((k, v)) = item else {
                    continue;
                };
                if *k > 0 {
                    continue;
                }
                *k *= 2;
                *v *= 3;
            }
            false
        });
        assert_eq!(map.len(), 3);
        assert_eq!(map.read_idx(0, |x| *x), Some((-6, 27)));
        assert_eq!(map.read_idx(1, |x| *x), Some((4, 8)));
        assert_eq!(map.read_idx(2, |x| *x), Some((5, 7)));
        assert_eq!(map.read_idx(3, |x| *x), None);
    }

    #[test]
    fn test_fixed_sized_map_array_sorting_order() {
        let map: FixedSizedMap<isize, usize, 5> = FixedSizedMap::new();
        map.set_default(1, 100).unwrap();
        map.set_default(2, 200).unwrap();
        map.set_default(-5, 300).unwrap();
        assert_eq!(
            *map.items.borrow(),
            [Some((-5, 300)), Some((1, 100)), Some((2, 200)), None, None,]
        );
    }

    #[test]
    fn test_fixed_sized_map_inner_join_keys() {
        let map1: FixedSizedMap<isize, usize, 5> = FixedSizedMap::new();
        assert!(map1.set_default(1, 100).unwrap());
        assert!(map1.set_default(20, 200).unwrap());
        assert!(map1.set_default(21, 300).unwrap());
        assert!(map1.set_default(5, 400).unwrap());
        assert_eq!(map1.len(), 4);

        let map2: FixedSizedMap<isize, usize, 5> = FixedSizedMap::new();
        assert!(map2.set_default(1, 500).unwrap());
        assert!(map2.set_default(20, 600).unwrap());
        assert!(map2.set_default(6, 700).unwrap());
        assert_eq!(map2.len(), 3);

        map1.inner_join_keys(&map2);
        assert_eq!(map1.len(), 2);
        assert_eq!(
            *map1.items.borrow(),
            [Some((1, 100)), Some((20, 200)), None, None, None,]
        );
    }
}
