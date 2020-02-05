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
#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

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
    0x06, 0xD0, 0xF1, /* USAGE_PAGE (FIDO CTAP) */
    0x09, 0x01,       /* USAGE (CTAPHID Usage) */
    0xA1, 0x01,       /* COLLECTION (Application) */
    0x09, 0x20,       /* USAGE (Input Report) */
    0x15, 0x00,       /* LOGICAL_MINIMUM (0) */
    0x26, 0xff, 0x00, /* LOGICAL_MAXIMUM (255) */
    0x75, 0x08,       /* REPORT_SIZE (8) */
    0x95, 0x40,       /* REPORT_COUNT (64) */
    0x81, 0x02,       /* INPUT (Data, Variable, Absolute) */
    0x09, 0x21,       /* USAGE (Output Report Data) */
    0x15, 0x00,       /* LOGICAL_MINIMUM (0) */
    0x26, 0xff, 0x00, /* LOGICAL_MAXIMUM (255) */
    0x75, 0x08,       /* RESPORT_SIZE (8) */
    0x95, 0x40,       /* REPORT_COUNT (64) */
    0x91, 0x02,       /* OUTPUT (Data, Variable, Absolute) */
    0xC0              /* END COLLECTION */
];

const DEFAULT_PATH: &str = "/dev/uhid";


#[derive(Copy, Clone)]
pub struct InputEvent {
    rec: Vec<u8>,
    rsp mut Vec<u8>,
    event: u8,
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
        //let mut create = event.u.create;
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
        //let event_output = event.u.output;

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
        //let mut uhid_input = event.u.input;
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


pub fn ctap_event(file: &mut File, event: &mut InputEvent) -> io::Result<()> {
    

    Ok(())
}
