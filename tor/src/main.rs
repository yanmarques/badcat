extern "C" {
    fn tor_main(argc: i32, argv: &Vec<&str>);
}

fn main() {
    unsafe {
        tor_main(1, &vec!["tor"]);
    }
}
