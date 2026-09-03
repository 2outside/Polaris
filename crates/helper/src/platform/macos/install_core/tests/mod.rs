use super::*;

#[test]
fn install_result_to_response_installed() {
    let resp = to_response(InstallResult::Installed);
    assert!(matches!(resp, Response::Ok(ResponseKind::Installed)));
}

#[test]
fn install_result_to_response_error_codes() {
    let resp = to_response(InstallResult::CoreDirUnset);
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::CoredirUnset,
            ..
        })
    ));

    let resp = to_response(InstallResult::BadArgs);
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::BadArgs,
            ..
        })
    ));

    let resp = to_response(InstallResult::HashMismatch);
    assert!(matches!(
        resp,
        Response::Err(ProtoError {
            code: ErrorCode::HashMismatch,
            ..
        })
    ));
}

#[test]
fn install_result_to_response_os_errors_keep_detail() {
    // read-singbox 等走 ErrorCode::Other + detail 保留完整原文
    let resp = to_response(InstallResult::ReadSingbox("open /x: no such file".into()));
    match resp {
        Response::Err(e) => {
            assert_eq!(e.code, ErrorCode::Other);
            assert!(e.detail.contains("read-singbox"), "{}", e.detail);
            assert!(e.detail.contains("no such file"), "{}", e.detail);
        }
        other => panic!("{other:?}"),
    }
}
