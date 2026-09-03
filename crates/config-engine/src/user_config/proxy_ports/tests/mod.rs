use super::*;

struct Cfg {
    mixed: Option<u16>,
    http: Option<u16>,
    control: Option<u16>,
}

impl PortConfig for Cfg {
    fn mixed_port(&self) -> Option<u16> {
        self.mixed
    }
    fn http_port(&self) -> Option<u16> {
        self.http
    }
    fn control_port(&self) -> Option<u16> {
        self.control
    }
}

#[test]
fn mixed_port_preferred() {
    assert_eq!(
        local_proxy_port(&Cfg {
            mixed: Some(7890),
            http: Some(2080),
            control: None
        }),
        7890
    );
}

#[test]
fn fallback_http_port() {
    assert_eq!(
        local_proxy_port(&Cfg {
            mixed: None,
            http: Some(2080),
            control: None
        }),
        2080
    );
}

#[test]
fn default_when_unset() {
    assert_eq!(
        local_proxy_port(&Cfg {
            mixed: None,
            http: None,
            control: None
        }),
        DEFAULT_MIXED_PORT
    );
}

#[test]
fn zero_treated_as_unset() {
    assert_eq!(
        local_proxy_port(&Cfg {
            mixed: Some(0),
            http: Some(1087),
            control: None
        }),
        1087
    );
}

#[test]
fn control_port() {
    assert_eq!(
        control_api_port(&Cfg {
            mixed: None,
            http: None,
            control: Some(9091)
        }),
        9091
    );
    assert_eq!(
        control_api_port(&Cfg {
            mixed: None,
            http: None,
            control: None
        }),
        DEFAULT_CONTROL_PORT
    );
}
