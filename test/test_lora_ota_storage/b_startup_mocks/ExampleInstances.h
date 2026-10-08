// Intentionally included separately inside each example's fixture namespace.
using b_example_fixture::InterfaceType;
b_example_fixture::State state;
InternalFileSystem InternalFS;
b_example_fixture::SerialPort Serial;
b_example_fixture::Board board{&state};
b_example_fixture::Radio radio_driver{&state};
b_example_fixture::Rng fast_rng;
b_example_fixture::Service sensors{&state, "sensors"}, rtc_clock{&state, "rtc"},
    external_watchdog{&state, "watchdog"};
b_example_fixture::Interfaces interface_manager{{&state, "interfaces"}};
b_example_fixture::Wifi WiFi{&state};
b_example_fixture::WifiInterface wifi_interface;
b_example_fixture::Store store{&state, &InternalFS};
b_example_fixture::Mesh the_mesh{&state, &InternalFS};

bool radio_init() { return state.radio_ok; }
mesh::LocalIdentity radio_new_identity() { return b_example_fixture::generateIdentity(state); }
bool otaBoardEarlyBootNormalProven() { ++state.preflights; return state.normal_proven; }
void halt() { throw b_example_fixture::Halt{}; }

void reset() {
  state = {};
  InternalFS = {};
  the_mesh = {&state, &InternalFS};
}
