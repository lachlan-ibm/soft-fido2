#!/bin/python
# Copyrite IBM 2022, 2025
# IBM Confidential

import logging, sys, os, argparse

# Set process title for proper notification display
try:
    from setproctitle import setproctitle
    setproctitle('AyeBeKey')
except ImportError:
    # setproctitle not available, notifications may show __main__.py
    pass
try:
    from .passkey_device import CTAP2HIDevice
    from .systray_app import SysTrayApp
    from .usbip_device import CTAP2USBIPDevice, USBContainer
except:
    try:
        sys.path.append(os.path.dirname(os.path.abspath(__file__)))
        from passkey_device import CTAP2HIDevice
        from systray_app import SysTrayApp
        from usbip_device import CTAP2USBIPDevice, USBContainer
    except Exception as e:
        logging.debug("Module load error")
        logging.exception(e)
        raise e


def main():
    """Main entry point with transport selection support"""
    
    # Parse command line arguments
    parser = argparse.ArgumentParser(
        description='FIDO2 Authenticator with multiple transport options',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run with UHID transport (default, requires /dev/uhid)
  python -m soft_fido2
  python -m soft_fido2 --transport uhid
  
  # Run with USB/IP transport (network-based, vhci driver required)
  python -m soft_fido2 --transport usbip
  
  # Run USB/IP on custom port
  python -m soft_fido2 --transport usbip --port 3240
        """
    )
    parser.add_argument(
        '--transport',
        choices=['uhid', 'usbip'],
        default='uhid',
        help='Transport layer to use (default: uhid)'
    )
    parser.add_argument(
        '--port',
        type=int,
        default=3240,
        help='Port for USB/IP transport (default: 3240)'
    )
    parser.add_argument(
        '--no-systray',
        action='store_true',
        help='Disable system tray icon (useful for USB/IP headless mode)'
    )
    
    args = parser.parse_args()
    
    # Setup logging
    if os.environ.get("FIDO_HOME") == None:
        sys.exit(1)
    ll = logging.INFO
    if "SOFT_FIDO2_DEBUG_LEVEL" in os.environ:
        ll = os.environ.get("SOFT_FIDO2_DEBUG_LEVEL")
    logFile = None # > stdout/stderr
    if "SOFT_FIDO2_LOG_FILE" in os.environ:
        logFile = os.path.join(
                            os.environ["FIDO_HOME"], os.environ["SOFT_FIDO2_LOG_FILE"])
    
    logging.basicConfig(level=ll, format='%(message)s', filename=logFile)
    
    # Start appropriate transport
    if args.transport == 'uhid':
        logging.info("Starting the AyeBeKey Passkey UHID Service")
        print("Starting the AyeBeKey Passkey UHID Service")
        
        udev = CTAP2HIDevice('/dev/uhid')
        udev.start()
        
        try:
            if not args.no_systray:
                app = SysTrayApp() # runs until quit
            else:
                # Run without systray - just wait for interrupt
                print("Running in headless mode (no system tray). Press Ctrl+C to stop.")
                import signal
                signal.pause()
        finally: # Ensure clean shutdown
            logging.info("Waiting for UHID device thread to terminate...")
            udev.join(timeout=5)
            if udev.is_alive():
                logging.warning("UHID device thread did not terminate gracefully")
            else:
                logging.info("UHID device thread terminated successfully")
    
    elif args.transport == 'usbip':
        logging.info("Starting the AyeBeKey Passkey USB/IP Service")
        print(f"Starting the AyeBeKey Passkey USB/IP Service on port {args.port}")
        print("Vendor ID: 0x3713, Product ID: 0x3713")
        print(f"Waiting for USB/IP client connection on port {args.port}...")
        print("\nOn CLIENT machine, run:")
        print("  $ sudo modprobe vhci-hcd")
        print(f"  $ sudo usbip list -r <SERVER_IP>")
        print(f"  $ sudo usbip attach -r <SERVER_IP> -b 1-1.1")
        print("  $ lsusb -v -d 3713:3713")
        
        # Create FIDO2 USB/IP device
        usb_dev = CTAP2USBIPDevice()
        
        # Create USB container and add device
        usb_container = USBContainer()
        usb_container.add_usb_device(usb_dev)
        
        # Run the USB/IP server
        try:
            usb_container.run()
        except KeyboardInterrupt:
            print("\nShutting down USB/IP authenticator...")
        except Exception as e:
            logging.error(f"Error running USB/IP authenticator: {e}")
            import traceback
            traceback.print_exc()
            raise

if __name__ == '__main__':
    main()
