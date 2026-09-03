use super::selected_file_label;
use std::path::Path;

#[test]
fn taildrop_diagnostics_do_not_include_parent_directories() {
    assert_eq!(
        selected_file_label(Path::new("/Users/alice/private/report.txt")),
        "report.txt"
    );
    assert_eq!(selected_file_label(Path::new("/")), "<selected-file>");
}
