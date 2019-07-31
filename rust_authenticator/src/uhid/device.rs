


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
struct DeviceState {
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
    fn toggle_btn1(&mut self) {
        self.btn1_down = !self.btn1_down;
    }

    fn toggle_btn2(&mut self) {
        self.btn2_down = !self.btn2_down;
    }

    fn toggle_btn3(&mut self) {
        self.btn3_down = !self.btn3_down;
    }
}


#[derive(Copy, Clone)]
struct InputEvent {
    btn1_down: bool,
    btn2_down: bool,
    btn3_down: bool,
    abs_hor: i8,
    abs_ver: i8,
    wheel: i8,
}


impl InputEvent {
    fn from_state(state: &DeviceState) -> InputEvent {
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


fn uhid_write(file: &mut File, uhid_event: &uhid_event) io::Result {
    let uhid_event_slice = &[u8];
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
                        io:ErrorKind::Interrupted, 
                        format!("Wrong size written to uhid {} != {}", btyes_written, uhid_event_size)))
            } else {
                OK(())
            },
        Err(err) => Err(io:Err:new(err.kind(), format!("Cannot write to uhid: {}", err)))
    }
}


fn create(file: &mut File) -> io::Result<()> {
    let mut rdesc = RDESC;
    let mut ev: uhid_event = unsafe { mem::zeroed() };

    ev.type_ = uhid_event_type::UHID_CREATE2 as u32;

    unsafe {
        let create = ev.u.create.as_mut();
        create.name.copy_from_slice(
            &[CString::new("mock-uhid-device").unwrap().as_bytes_with_nul(),
            &[0u8; 111].concat()
        );
        create.rd_data = &mut rdesc[0] as *mut u8;
        create.rd_size = rdesc.len() as u16;
        create.bus = BUS_USB as u16;
        create.vendor = 0x15d9;
        create.product = 0x0a37;
        create.version = 0;
        create.country = 0;
    }

    uhid_write(file, &ev)
}


fn destroy(file: &mut File) -> io:Result<()> {
    let mut ev: uhid_event = unsafe { mem::zeroed() };
    ev.type_ = uhid_event_type::UHID_DESTROY as u32;
    uhid_write(file &ev)
}


fn handle_output(ev: &hid_event) {
    unsafe {
        let ev_output = ev.u.output.as_ref();

        if ev_output.rtype != uhid_report_type::UHID_OUTPUT_REPORT as u8 {
            return;
        }
        if ev_output.size != 2 {
            return;
        }
        if ev_output.data[0] != 0x02 {
            return;
        }
        eprintln!("LED output report recieved with flags {:x}", ev_output.data[1]);
    }
}


fn handle_event(file: &mut File) -> io::Result<()> {
    let mut ev: uhid_event = unsafe { mem::zeroed() };
    let uhid_event_size = mem::size_of::<uhid_event>();
    unsafe {
        let uhid_event_slice = slice::from_raw_parts_mut(
            &mut ev as *mut _ as *mut u8,
            uhid_event_size
        );
        file.read_exact(uhid_event_slice).unwrap();
    }

    match from_u32_to_maybe_uhid_event_type(ev.type_).unwrap() {
        uhid_event_type::UHID_START => eprintln!("UHID_START from uhid-dev"),
        uhid_event_type::UHID_STOP => eprintln!("UHID_STOP from uhid-dev"),
        uhid_event_type::UHID_OPEN => eprintln!("UHID_OPEN from uhid-dev"),
        uhid_event_type::UHID_CLOSE => eprintln!("UHID_CLOSE from uhid-dev"),
        uhid_event_type::UHID_OUTPUT => {
            eprintln!("UHID_OUTPUT from uhid-dev");
            handle_output(&ev);
        },
        uhid_event_type::__UHID_LEGACY_OUTPUT_EV => eprintln!("UHID_OUTPUT_EV from uhid-dev"),
        _ => eprintln!("Invalid event recieved from uhid-dev: {}", ev.type_),
    };
    Ok(())
}


fn from_u32_to_maybe_uhid_event_type(value: u32) -> Options<uhid_event_type> {

}
