pub mod help;
pub mod receive_code;

macro_rules! my_commands {
    () => {
        vec![
            commands::help::help(),
            commands::receive_code::receive_code(),
        ]
    };
}
