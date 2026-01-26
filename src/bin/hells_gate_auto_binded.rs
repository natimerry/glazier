use libwinexploit::winapi::HANDLE;
use libwinexploit::winapi::NTSTATUS;
use libwinexploit::winapi::NtAllocateVirtualMemoryHellsGate;
use libwinexploit::winapi::PVOID;
use std::ptr;

const MEM_COMMIT: u32 = 0x1000;
const MEM_RESERVE: u32 = 0x2000;
const PAGE_READWRITE: u32 = 0x04;

fn main() {
    let process_handle: HANDLE = -1isize as HANDLE;

    let mut base_address: PVOID = ptr::null_mut(); // Let the OS choose the address
    let zero_bits: u64 = 0;
    let mut region_size: u64 = 0x10000;

    let allocation_type: u32 = MEM_COMMIT | MEM_RESERVE;
    let protect: u32 = PAGE_READWRITE;

    println!("Requested allocation size: 0x{:X} bytes", region_size);
    println!("Allocation type: MEM_COMMIT | MEM_RESERVE");
    println!("Protection: PAGE_READWRITE\n");

    let status: NTSTATUS = unsafe {
        NtAllocateVirtualMemoryHellsGate(
            process_handle,
            &mut base_address as *mut _,
            zero_bits,
            &mut region_size as *mut _,
            allocation_type,
            protect,
        )
    };

    if status == 0 {
        println!("Memory allocated via direct syscall");
        println!("\tBase Address: {:?}", base_address);
        println!("\tRegion Size:  0x{:X} bytes\n", region_size);

        unsafe {
            let ptr = base_address as *mut u8;

            for i in 0..16 {
                *ptr.add(i) = (0xAA + i) as u8;
            }

            println!("Successfully wrote test pattern to allocated memory");

            print!("\tFirst 16 bytes: ");
            for i in 0..16 {
                print!("{:02X} ", *ptr.add(i));
            }
            println!("\n");
        }
    } else {
        println!("Failed with NTSTATUS: 0x{:08X}", status as u32);

        // Common error codes:
        match status as u32 {
            0xC0000017 => println!("\tError: STATUS_NO_MEMORY - Insufficient memory"),
            0xC000000D => println!("\tError: STATUS_INVALID_PARAMETER - Invalid parameter"),
            0xC0000018 => println!("\tError: STATUS_CONFLICTING_ADDRESSES - Address conflict"),
            _ => println!("\tError: Unknown NTSTATUS code"),
        }
    }
}
