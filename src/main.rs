pub mod find_target;

use find_target;

fn main() {
    println!("Hello, world!");
    let matching_processes = find_target::get_processes_by_image_name("notepad.exe");
    for proc in matching_processes {
        println!("Found process: {:?}", proc);
    }
}
