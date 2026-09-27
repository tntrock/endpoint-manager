//! schema v1 的樣本必須永遠能被解析（伺服器需相容舊版 Agent）。

use protocol::{CheckinRequest, InventoryPayload, InventoryUpload, Section};

#[test]
fn v1_checkin_parses() {
    let r: CheckinRequest = serde_json::from_str(include_str!("fixtures/v1/checkin.json")).unwrap();
    assert_eq!(r.section_hashes[&Section::Software], "abc");
    assert_eq!(r.section_errors[&Section::Patches], "WMI timeout");
}

#[test]
fn v1_software_upload_parses() {
    let u: InventoryUpload =
        serde_json::from_str(include_str!("fixtures/v1/software.json")).unwrap();
    match u.payload {
        InventoryPayload::Software(v) => assert_eq!(v.len(), 2),
        other => panic!("unexpected {other:?}"),
    }
}
