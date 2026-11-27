//! Endpoint scope and record-filter wire contract tests.
#![allow(clippy::unwrap_used)] // Assertions deliberately panic on invalid snapshots.
use super::raw_event::OsFamily;
use super::*;

fn check<T: Serialize + serde::de::DeserializeOwned + Eq + std::fmt::Debug>(
    value: &T,
    expected: &[u8],
) {
    let bytes = bincode::serde::encode_to_vec(value, bincode::config::standard()).unwrap();
    assert_eq!(bytes, expected);
    let (decoded, used): (T, _) =
        bincode::serde::decode_from_slice(expected, bincode::config::standard()).unwrap();
    assert_eq!(used, expected.len());
    assert_eq!(&decoded, value);
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the independent wire snapshots together.
fn endpoint_and_filter_wire_bytes_are_pinned() {
    check(&EndpointScope::All, &[0]);
    check(
        &EndpointScope::Groups(vec!["g".into(), "h".into()]),
        &[1, 2, 1, 103, 1, 104],
    );
    check(
        &EndpointSourcesRequest::Training { run_id: 300 },
        &[0, 251, 44, 1],
    );
    check(
        &EndpointSourcesRequest::Round {
            detector_id: -3,
            model: "host".into(),
        },
        &[1, 5, 4, 104, 111, 115, 116],
    );
    check(
        &EndpointSources {
            endpoints: vec!["01234567-89ab-cdef-0123-456789abcdef".into()],
            os_family: OsFamily::Windows,
        },
        &[
            1, 36, 48, 49, 50, 51, 52, 53, 54, 55, 45, 56, 57, 97, 98, 45, 99, 100, 101, 102, 45,
            48, 49, 50, 51, 45, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102, 0,
        ],
    );
    check(
        &EndpointSources {
            endpoints: vec![],
            os_family: OsFamily::Linux,
        },
        &[0, 1],
    );
    check(
        &RecordFilterCounts {
            not_extended: 0,
            other_os: 0,
        },
        &[0, 0],
    );
    check(
        &DayFilterCounts {
            start: 1_700_000_000_000_000_001,
            counts: RecordFilterCounts {
                not_extended: 0,
                other_os: 300,
            },
        },
        &[253, 2, 0, 84, 108, 252, 57, 47, 47, 0, 251, 44, 1],
    );
    check(
        &TrainingFilterReport {
            endpoint_sources: 2,
            days: vec![DayFilterCounts {
                start: 1_700_000_000_000_000_001,
                counts: RecordFilterCounts {
                    not_extended: 0,
                    other_os: 300,
                },
            }],
        },
        &[2, 1, 253, 2, 0, 84, 108, 252, 57, 47, 47, 0, 251, 44, 1],
    );
    check(
        &RoundFilterReport {
            finished_at: -1_700_000_000_000_000_001,
            served_sources: 1,
            counts: RecordFilterCounts {
                not_extended: 300,
                other_os: 0,
            },
        },
        &[253, 1, 0, 84, 108, 252, 57, 47, 47, 1, 251, 44, 1, 0],
    );
    check(
        &(
            7_u32,
            TrainingFilterReport {
                endpoint_sources: 2,
                days: vec![DayFilterCounts {
                    start: 1_700_000_000_000_000_001,
                    counts: RecordFilterCounts {
                        not_extended: 0,
                        other_os: 300,
                    },
                }],
            },
        ),
        &[7, 2, 1, 253, 2, 0, 84, 108, 252, 57, 47, 47, 0, 251, 44, 1],
    );
    check(
        &(
            -3_i32,
            "host".to_string(),
            RoundFilterReport {
                finished_at: -1_700_000_000_000_000_001,
                served_sources: 1,
                counts: RecordFilterCounts {
                    not_extended: 300,
                    other_os: 0,
                },
            },
        ),
        &[
            5, 4, 104, 111, 115, 116, 253, 1, 0, 84, 108, 252, 57, 47, 47, 1, 251, 44, 1, 0,
        ],
    );
    check(
        &TrainingFilterReport {
            endpoint_sources: 0,
            days: vec![],
        },
        &[0, 0],
    );
}
