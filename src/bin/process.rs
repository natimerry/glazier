use glazier::runtime::process::*;

const PROCESS_ALL_ACCESS: u32 = 0x001f_ffff;

fn main() {
    let process = Process::get_from_name("msedge.exe", PROCESS_ALL_ACCESS).unwrap();
    for process in process {
        println!("PID: {:#?}", process);
    }
}
