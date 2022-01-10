use std::{mem, ptr};
use std::alloc::{alloc, Layout};

pub unsafe fn c_array<T>(items: Vec<T>) -> *mut u8
where T: Copy, {
    // How many records to allocate
    let mem_layout = Layout::array::<T>(items.len()).unwrap();

    // Allocate memory and return a pointer
    let raw_ptr = alloc(mem_layout);

    // Figure the size of each item in the list
    let item_size = mem::size_of::<T>();

    for (i, item) in items.iter().enumerate() {
        // Next array address
        let addr = raw_ptr as usize + (i * item_size);

        ptr::write(addr as *mut T, *item);
    }

    raw_ptr
}

pub fn copy_buf<T>(dst: &mut [T], src: &[T])
where T: Copy, {
    assert_eq!(dst.len(), src.len());

    let mut index = 0;

    for value in src {
        dst[index] = *value;
        index += 1;
    }
}