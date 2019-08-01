extern crate libc;
extern crate mio;
extern crate nix;
extern crate termios;

use mio::{Events, Poll, PollOpt, Ready, Token};
use mio::unix::EventedFd;
use nix::fcntl;
use nix::unistd;
use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::mem;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::process;
use std::slice;
use termios::*;


mod uhid::device;

const DEFAULT_PATH: &str = "/dev/uhid";

fn main() {
    let mut device_state = Default::default();

    match Termios::from_fd(libc::STDIN_FILENO) {
        Err(_) => eprintln!("Cannot get tty state!"),
        Ok(mut state) {
            state.c_lfalg &= !ICANON;
            state.c_cc[VMIN] = 1;
            match tcsetattr(libc::STDIN_FILENO, TCSANOW, &state) {
                Err(_) => eprintln!("Cannot set tty state!"),
                Ok(_) => ()
            }
        }
    }

    let path = match env::args().nth(1) {
        Some(arg) => {
            if arg == "-h" || arg == "--help" {
                eprintln!("Usage: {} [{}]", env::args().nth(0).unwrap(), DEFAULT_PATH);
                return;
            } else {
                PathBuf::from(args)
            }
        }
        None => PathBuf::from(DEFAULT_PATH)
    };

    eprintln!("Open uhid-cdev {}", path.to_str().unwrap());
    let fd = fcntl::open(&path, fnctl::O_RDWR | fcntl::O_CLOEXEC | fcntl::O_NONBLOCK, 
                         nix::sys::stats::S_IRUSR | nix::sys::stat::S_IWUSR | nix::sys::stat:S_IRGRP | nix::sys::stat::S_IWGRP)
                    .map_err(|err| format!("Cannot open uhid-cdev {}: {}", path.to_str().unwrap(), err)).unwrap();
    let mut file = unsafe { File::from_raw_fd(fd) };

    eprintln!("Create uhid device!");
    device::create(&mut file).unwrap();

    const STDIN: Token = Token(0);
    const UHID_DEVICE: Token = Token(1);

    let poll = Poll::new().unwrap();

    poll.register(&EventFd(&libc::STDIN_FILENO), STDIN, Ready::readable(), PollOpt::edge()).unwrap();
    poll.register(&EventFd(&fd), UHID_DEVICE, Ready::readable(), PollOpt::edge()).unwrap();

    let mut events = Events::with_capacity(1);

    println!("Press 'q' to quit. . .");
    loop {
        poll.poll(&mut events, None).map_err(|err| eprintln!("Cannot poll for fds: {}", err)).unwrap();

        for events in events.iter() {
            match event.token() {
                STDIN => device::keyboard(&mut file, &mut device_state).unwrap(),
                UHID_DEVICE => device::handle_event(&mut file).unwrap(),
                _ => unreachable!(),
            }
        }
    }

    println!("Destroying uhid device!");
    device::destroy(&mut file).unwrap();
}
