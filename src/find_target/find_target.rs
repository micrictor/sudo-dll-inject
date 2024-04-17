use tasklist;

// Get the list of processes that match a provided image name
fn get_processes_by_image_name(image_name: &str) -> Vec<tasklist::Process> {
    let matching_processes: Vec<tasklist::Process> = vec![];
    let tl: tasklist::Tasklist;
    // Iterate over the list of processes and check if the image name matches
    unsafe {
        let tl: tasklist::Tasklist = tasklist::Tasklist::new();
        for process in tl.processes() {
            // Do a case insensitive match on image name
            if process.image_name().to_lowercase() == image_name.to_lowercase() {
                matching_processes.push(process);
            }
        }
    }
    matching_processes
}
