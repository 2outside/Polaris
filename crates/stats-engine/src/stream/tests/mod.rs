use super::*;

#[test]
fn vec_status_stream_yields_in_order_then_none() {
    let mut s = VecStatusStream::new(vec![
        SingBoxStatus {
            uplink: 1,
            ..Default::default()
        },
        SingBoxStatus {
            uplink: 2,
            ..Default::default()
        },
    ]);
    assert_eq!(s.next().unwrap().uplink, 1);
    assert_eq!(s.next().unwrap().uplink, 2);
    assert!(s.next().is_none());
}

#[test]
fn vec_status_stream_empty_yields_none_immediately() {
    let mut s = VecStatusStream::new(vec![]);
    assert!(s.next().is_none());
}

#[test]
fn vec_connection_event_stream_yields_then_none() {
    let mut s = VecConnectionEventStream::new(vec![
        SingBoxConnectionEvents::default(),
        SingBoxConnectionEvents {
            reset: true,
            ..Default::default()
        },
    ]);
    assert!(!s.next().unwrap().reset);
    assert!(s.next().unwrap().reset);
    assert!(s.next().is_none());
}

#[test]
fn status_stream_is_object_safe() {
    // 确认可用 trait object（dyn StatusStream）——上层 actor 会装箱多种实现。
    let s: Box<dyn StatusStream> = Box::new(VecStatusStream::new(vec![SingBoxStatus {
        uplink: 42,
        ..Default::default()
    }]));
    let mut s = s;
    assert_eq!(s.next().unwrap().uplink, 42);
}

#[test]
fn connection_event_stream_is_object_safe() {
    let s: Box<dyn ConnectionEventStream> = Box::new(VecConnectionEventStream::new(vec![]));
    let mut s = s;
    assert!(s.next().is_none());
}
