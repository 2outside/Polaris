use super::*;

#[test]
fn liveness_only_treats_explicit_absence_as_dead() {
    assert_eq!(
        liveness_from_probe(Some(ERROR_INVALID_PARAMETER), None),
        Liveness::Dead
    );
    assert_eq!(liveness_from_probe(Some(5), None), Liveness::Unknown);
    assert_eq!(liveness_from_probe(None, None), Liveness::Unknown);
    assert_eq!(
        liveness_from_probe(None, Some(STILL_ACTIVE_CODE)),
        Liveness::Alive
    );
    assert_eq!(liveness_from_probe(None, Some(0)), Liveness::Dead);
}
