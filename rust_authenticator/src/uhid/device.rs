/*
 * UHID Example
 *
 * Copyright (c) 2012-2013 David Herrmann <dh.herrmann@gmail.com>
 *
 * Converted from C to rust by Daniel Stiner <daniel.stiner@gmail.com>
 *
 * The code may be used by anyone for any purpose,
 * and can serve as a starting point for developing
 * applications using uhid.
 */

extern crate libc;
extern crate mio;

use std::env;
use std::ffi::CString;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::mem;
use std::os::unix::io::FromRawFd;
use std::process;
use std::slice;

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));


const RDESC: [u8; 85] = [
    0x05, 0x01, /* USAGE_PAGE (Generic Desktop) */
    0x09, 0x02, /* USAGE (Mouse) */
    0xa1, 0x01, /* COLLECTION (Application) */
    0x09, 0x01,     /* USAGE (Pointer) */
    0xa1, 0x00,     /* COLLECTION (Physical) */
    0x85, 0x01,         /* REPORT_ID (1) */
    0x05, 0x09,         /* USAGE_PAGE (Button) */
    0x19, 0x01,         /* USAGE_MINIMUM (Button 1) */
    0x29, 0x03,         /* USAGE_MAXIMUM (Button 3) */
    0x15, 0x00,         /* LOGICAL_MINIMUM (0) */
    0x25, 0x01,         /* LOGICAL_MAXIMUM (1) */
    0x95, 0x03,         /* REPORT_COUNT (3) */
    0x75, 0x01,         /* REPORT_SIZE (1) */
    0x81, 0x02,         /* INPUT (Data,Var,Abs) */
    0x95, 0x01,         /* REPORT_COUNT (1) */
    0x75, 0x05,         /* REPORT_SIZE (5) */
    0x81, 0x01,         /* INPUT (Cnst,Var,Abs) */
    0x05, 0x01,         /* USAGE_PAGE (Generic Desktop) */
    0x09, 0x30,         /* USAGE (X) */
    0x09, 0x31,         /* USAGE (Y) */
    0x09, 0x38,         /* USAGE (WHEEL) */
    0x15, 0x81,         /* LOGICAL_MINIMUM (-127) */
    0x25, 0x7f,         /* LOGICAL_MAXIMUM (127) */
    0x75, 0x08,         /* REPORT_SIZE (8) */
    0x95, 0x03,         /* REPORT_COUNT (3) */
    0x81, 0x06,         /* INPUT (Data,Var,Rel) */
    0xc0,           /* END_COLLECTION */
    0xc0,       /* END_COLLECTION */
    0x05, 0x01, /* USAGE_PAGE (Generic Desktop) */
    0x09, 0x06, /* USAGE (Keyboard) */
    0xa1, 0x01, /* COLLECTION (Application) */
    0x85, 0x02,     /* REPORT_ID (2) */
    0x05, 0x08,     /* USAGE_PAGE (Led) */
    0x19, 0x01,     /* USAGE_MINIMUM (1) */
    0x29, 0x03,     /* USAGE_MAXIMUM (3) */
    0x15, 0x00,     /* LOGICAL_MINIMUM (0) */
    0x25, 0x01,     /* LOGICAL_MAXIMUM (1) */
    0x95, 0x03,     /* REPORT_COUNT (3) */
    0x75, 0x01,     /* REPORT_SIZE (1) */
    0x91, 0x02,     /* Output (Data,Var,Abs) */
    0x95, 0x01,     /* REPORT_COUNT (1) */
    0x75, 0x05,     /* REPORT_SIZE (5) */
    0x91, 0x01,     /* Output (Cnst,Var,Abs) */
    0xc0,       /* END_COLLECTION */
];

const DEFAULT_PATH: &str = "/dev/uhid";


#[derive(Clone, Copy)]
pub struct DeviceState {
    btn1_down: bool,
    btn2_down: bool,
    btn3_down: bool,
}

impl Default for DeviceState {
    fn default() -> DeviceState {
        DeviceState {
            btn1_down: false,
            btn2_down: false,
            btn3_down: false,
        }
    }
}


impl DeviceState {
    pub fn toggle_btn1(&mut self) {
        self.btn1_down = !self.btn1_down;
    }

    pub fn toggle_btn2(&mut self) {
        self.btn2_down = !self.btn2_down;
    }

    pub fn toggle_btn3(&mut self) {
        self.btn3_down = !self.btn3_down;
    }
}


#[derive(Copy, Clone)]
pub struct InputEvent {
    btn1_down: bool,
    btn2_down: bool,
    btn3_down: bool,
    abs_hor: i8,
    abs_ver: i8,
    wheel: i8,
}


impl InputEvent {
    pub fn from_state(state: &DeviceState) -> InputEvent {
        InputEvent {
            btn1_down: state.btn1_down,
            btn2_down: state.btn2_down,
            btn3_down: state.btn3_down,
            abs_hor: 0,
            abs_ver: 0,
            wheel: 0,
        }
    }
}


pub fn uhid_write(file: &mut File, uhid_event: &uhid_event) -> io::Result<()> {
    let uhid_event_slice: &[u8];
    let uhid_event_size = mem::size_of::<uhid_event>();

    unsafe {
        uhid_event_slice = slice::from_raw_parts(
            uhid_event as *const _ as *const u8,
            uhid_event_size,
        );
    }
    match file.write(uhid_event_slice) {
        Ok(bytes_written) =>
            if bytes_written != uhid_event_size {
                Err(io::Error::new(
                        io::ErrorKind::Interrupted, 
                        format!("Wrong size written to uhid {} != {}", bytes_written, uhid_event_size)))
            } else {
                Ok(())
            },
        Err(err) => Err(io::Error::new(err.kind(), format!("Cannot write to uhid: {}", err)))
    }
}


pub fn create(file: &mut File) -> io::Result<()> {
    let mut rdesc = RDESC;
    let mut event: uhid_event = unsafe { mem::zeroed() };

    event.type_ = uhid_event_type::__UHID_LEGACY_CREATE as u32;

    unsafe {
        let create = event.u.create.as_mut();
        create.name.copy_from_slice(
            &[CString::new("mock-uhid-device").unwrap().as_bytes_with_nul(),
            &[0u8; 111]].concat());
        create.rd_data = &mut rdesc[0] as *mut u8;
        create.rd_size = rdesc.len() as u16;
        create.bus = BUS_USB as u16;
        create.vendor = 0x15d9;
        create.product = 0x0a37;
        create.version = 0;
        create.country = 0;
    }

    uhid_write(file, &event)
}


pub fn destroy(file: &mut File) -> io::Result<()> {
    let mut event: uhid_event = unsafe { mem::zeroed() };
    event.type_ = uhid_event_type::UHID_DESTROY as u32;
    uhid_write(file, &event)
}


pub fn handle_output(event: &uhid_event) {
    unsafe {
        let event_output = event.u.output.as_ref();

        if event_output.rtype != uhid_report_type::UHID_OUTPUT_REPORT as u8 {
            return;
        }
        if event_output.size != 2 {
            return;
        }
        if event_output.data[0] != 0x02 {
            return;
        }
        eprintln!("LED output report recieved with flags {:x}", event_output.data[1]);
    }
}


pub fn handle_event(file: &mut File) -> io::Result<()> {
    let mut event: uhid_event = unsafe { mem::zeroed() };
    let uhid_event_size = mem::size_of::<uhid_event>();
    unsafe {
        let uhid_event_slice = slice::from_raw_parts_mut(
            &mut event as *mut _ as *mut u8,
            uhid_event_size
        );
        file.read_exact(uhid_event_slice).unwrap();
    }

    match from_u32_to_maybe_uhid_event_type(event.type_).unwrap() {
        uhid_event_type::UHID_START => eprintln!("UHID_START from uhid-dev"),
        uhid_event_type::UHID_STOP => eprintln!("UHID_STOP from uhid-dev"),
        uhid_event_type::UHID_OPEN => eprintln!("UHID_OPEN from uhid-dev"),
        uhid_event_type::UHID_CLOSE => eprintln!("UHID_CLOSE from uhid-dev"),
        uhid_event_type::UHID_OUTPUT => {
            eprintln!("UHID_OUTPUT from uhid-dev");
            handle_output(&event);
        },
        uhid_event_type::__UHID_LEGACY_OUTPUT_EV => eprintln!("UHID_OUTPUT_EV from uhid-dev"),
        _ => eprintln!("Invalid event recieved from uhid-dev: {}", event.type_),
    };
    Ok(())
}


pub fn from_u32_to_maybe_uhid_event_type(value: u32) -> Option<uhid_event_type> {
    if value == uhid_event_type::__UHID_LEGACY_CREATE as u32 {
        Some(uhid_event_type::__UHID_LEGACY_CREATE)
    } else if value == uhid_event_type::UHID_DESTROY as u32 {
        Some(uhid_event_type::UHID_DESTROY)
    } else if value == uhid_event_type::UHID_START as u32 {
        Some(uhid_event_type::UHID_START)
    } else if value == uhid_event_type::UHID_STOP as u32 {
        Some(uhid_event_type::UHID_STOP)
    } else if value == uhid_event_type::UHID_OPEN as u32 {
        Some(uhid_event_type::UHID_OPEN)
    } else if value == uhid_event_type::UHID_CLOSE as u32 {
        Some(uhid_event_type::UHID_CLOSE)
    } else if value == uhid_event_type::UHID_OUTPUT as u32 {
        Some(uhid_event_type::UHID_OUTPUT)
    } else if value == uhid_event_type::__UHID_LEGACY_OUTPUT_EV as u32 {
        Some(uhid_event_type::__UHID_LEGACY_OUTPUT_EV)
    } else if value == uhid_event_type::__UHID_LEGACY_INPUT as u32 {
        Some(uhid_event_type::__UHID_LEGACY_INPUT)
    } else if value == uhid_event_type::UHID_GET_REPORT as u32 {
        Some(uhid_event_type::UHID_GET_REPORT)
    } else if value == uhid_event_type::UHID_GET_REPORT_REPLY as u32 {
        Some(uhid_event_type::UHID_GET_REPORT_REPLY)
    } else if value == uhid_event_type::UHID_CREATE2 as u32 {
        Some(uhid_event_type::UHID_CREATE2)
    } else if value == uhid_event_type::UHID_INPUT2 as u32 {
        Some(uhid_event_type::UHID_INPUT2)
    } else if value == uhid_event_type::UHID_SET_REPORT as u32 {
        Some(uhid_event_type::UHID_SET_REPORT)
    } else if value == uhid_event_type::UHID_SET_REPORT_REPLY as u32 {
        Some(uhid_event_type::UHID_SET_REPORT_REPLY)
    } else {
        None
    }
}


pub fn send_event(file: &mut File, input: &InputEvent) -> io::Result<()> {
    let mut event: uhid_event = unsafe { mem::zeroed() };

    event.type_ = uhid_event_type::__UHID_LEGACY_INPUT as u32;

    unsafe {
        let uhid_input = event.u.input.as_mut();
        uhid_input.size = 5;
        uhid_input.data[0] = 0x01;
        if input.btn1_down {
            uhid_input.data[1] |= 0x01;
        }
        if input.btn2_down {
            uhid_input.data[1] |= 0x02;
        }
        if input.btn3_down {
            uhid_input.data[1] |= 0x04;
        }
        uhid_input.data[2] = input.abs_hor as u8;
        uhid_input.data[3] = input.abs_ver as u8;
        uhid_input.data[4] = input.wheel as u8;
    }
    uhid_write(file, &event)
}


pub fn keyboard(file: &mut File, state: &mut DeviceState) -> io::Result<()> {
    let mut character: [u8; 1] = Default::default();
    io::stdin().read(&mut character)?;

    let input_event = match character[0] {
         b'1' => {
             state.toggle_btn1();
             InputEvent::from_state(state)
        },
        b'2' => {
             state.toggle_btn2();
             InputEvent::from_state(state)
        },
        b'3' => {
            state.toggle_btn3();
            InputEvent::from_state(state)
        },
        b'a' => {
            let mut input = InputEvent::from_state(state);
            input.abs_hor = -20;
            input
        },
        b'd' => {
            let mut input = InputEvent::from_state(state);
            input.abs_hor = 20;
            input
        },
        b'w' => {
            let mut input = InputEvent::from_state(state);
            input.abs_ver = -20;
            input
        },
        b's' => {
            let mut input = InputEvent::from_state(state);
            input.abs_ver = 20;
            input
        },
        b'r' => {
            let mut input = InputEvent::from_state(state);
            input.wheel = 1;
            input
        },
        b'f' => {
            let mut input = InputEvent::from_state(state);
            input.wheel = -1;
            input
        },
        b'q' => {
            return Err(io::Error::new(io::ErrorKind::Other, "Cancelled!"));
        },
        c => {
            eprintln!("Invalid input: {}", c as char);
            return Ok(())
        }
    };

    send_event(file, &input_event)?;

    Ok(())
}
