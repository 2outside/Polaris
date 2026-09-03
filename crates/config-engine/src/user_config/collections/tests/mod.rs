use super::*;

#[test]
fn dedupe_preserves_order() {
    assert_eq!(dedupe(vec![3, 1, 2, 1, 3, 4]), vec![3, 1, 2, 4]);
}

#[test]
fn dedupe_strings() {
    assert_eq!(
        dedupe(vec!["a".to_string(), "b".to_string(), "a".to_string()]),
        vec!["a".to_string(), "b".to_string()]
    );
}

#[test]
fn dedupe_trim_filters_empty() {
    assert_eq!(
        dedupe_trim(vec![
            "  a  ".into(),
            "b".into(),
            "".into(),
            "  ".into(),
            "a".into()
        ]),
        vec!["a".to_string(), "b".to_string()]
    );
}
