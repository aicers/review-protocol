//! `REview` request envelope; bincode standard bodies follow an LE fixed-width code.
use serde::Serialize;

#[derive(Serialize)]
pub(crate) struct Request<T> {
    code: [u8; 4],
    payload: T,
}

pub(crate) fn request<T>(code: u32, payload: T) -> Request<T> {
    Request {
        code: code.to_le_bytes(),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn agent_request_code_snapshots() {
        for (code, expected) in [
            (crate::client::RequestCode::DnsStart, 1_u32),
            (crate::client::RequestCode::DnsStop, 2_u32),
            (crate::client::RequestCode::Reboot, 4_u32),
            (crate::client::RequestCode::ReloadConfig, 6_u32),
            (crate::client::RequestCode::ReloadTi, 5_u32),
            (crate::client::RequestCode::ResourceUsage, 7_u32),
            (crate::client::RequestCode::TorExitNodeList, 8_u32),
            (crate::client::RequestCode::SamplingPolicyList, 9_u32),
            (crate::client::RequestCode::ReloadFilterRule, 10_u32),
            (crate::client::RequestCode::UpdateConfig, 12_u32),
            (crate::client::RequestCode::DeleteSamplingPolicy, 13_u32),
            (crate::client::RequestCode::InternalNetworkList, 14_u32),
            (crate::client::RequestCode::Allowlist, 15_u32),
            (crate::client::RequestCode::Blocklist, 16_u32),
            (crate::client::RequestCode::EchoRequest, 17_u32),
            (crate::client::RequestCode::TrustedUserAgentList, 18_u32),
            (crate::client::RequestCode::TrustedDomainList, 0_u32),
            (crate::client::RequestCode::ProcessList, 19_u32),
            (crate::client::RequestCode::SemiSupervisedModels, 20_u32),
            (crate::client::RequestCode::Shutdown, 21_u32),
            (crate::client::RequestCode::DeleteCustomerData, 22_u32),
            (crate::client::RequestCode::NodeService, 100_u32),
            (crate::client::RequestCode::NodeNetworkInterface, 101_u32),
            (crate::client::RequestCode::NodeHostname, 102_u32),
            (crate::client::RequestCode::NodeTimeSync, 103_u32),
            (crate::client::RequestCode::NodeLogging, 104_u32),
            (crate::client::RequestCode::NodeRemoteAccess, 105_u32),
            (crate::client::RequestCode::NodePower, 106_u32),
            (crate::client::RequestCode::NodeObservation, 107_u32),
            (crate::client::RequestCode::NodeVersion, 108_u32),
            (crate::client::RequestCode::NodePackage, 109_u32),
            (crate::client::RequestCode::NodeEnroll, 110_u32),
            (crate::client::RequestCode::Unknown, u32::MAX),
        ] {
            assert_eq!(u32::from(code), expected);
            let bytes = bincode::serde::encode_to_vec(
                request(u32::from(code), 300_u32),
                bincode::config::standard(),
            )
            .unwrap();
            assert_eq!(bytes.get(..4).unwrap(), expected.to_le_bytes());
            assert_eq!(bytes.get(4..).unwrap(), &[251, 44, 1]);
        }
    }
    #[test]
    fn server_request_code_snapshots() {
        for (code, expected) in [
            (crate::server::RequestCode::GetDataSource, 0_u32),
            (crate::server::RequestCode::GetIndicator, 1_u32),
            (crate::server::RequestCode::GetMaxEventIdNum, 2_u32),
            (crate::server::RequestCode::GetModel, 3_u32),
            (crate::server::RequestCode::GetModelNames, 4_u32),
            (crate::server::RequestCode::InsertColumnStatistics, 5_u32),
            (crate::server::RequestCode::InsertModel, 6_u32),
            (crate::server::RequestCode::InsertTimeSeries, 7_u32),
            (crate::server::RequestCode::RemoveModel, 8_u32),
            (crate::server::RequestCode::RemoveOutliers, 9_u32),
            (crate::server::RequestCode::UpdateClusters, 10_u32),
            (crate::server::RequestCode::UpdateModel, 11_u32),
            (crate::server::RequestCode::UpdateOutliers, 12_u32),
            (crate::server::RequestCode::InsertEventLabels, 13_u32),
            (crate::server::RequestCode::GetDataSourceList, 14_u32),
            (crate::server::RequestCode::GetLabelDbPatterns, 15_u32),
            (crate::server::RequestCode::InsertDataSource, 20_u32),
            (crate::server::RequestCode::RenewCertificate, 23_u32),
            (crate::server::RequestCode::GetTrustedDomainList, 24_u32),
            (crate::server::RequestCode::GetOutliers, 25_u32),
            (crate::server::RequestCode::GetTorExitNodeList, 26_u32),
            (crate::server::RequestCode::GetInternalNetworkList, 31_u32),
            (crate::server::RequestCode::GetAllowlist, 32_u32),
            (crate::server::RequestCode::GetBlocklist, 33_u32),
            (crate::server::RequestCode::GetPretrainedModel, 34_u32),
            (crate::server::RequestCode::GetTrustedUserAgentList, 35_u32),
            (crate::server::RequestCode::GetConfig, 36_u32),
            (crate::server::RequestCode::UpdateHostOpenedPorts, 37_u32),
            (crate::server::RequestCode::UpdateHostOsAgents, 38_u32),
            (crate::server::RequestCode::GetSamplingPolicyList, 39_u32),
            (
                crate::server::RequestCode::ReportCustomerDataDeletion,
                40_u32,
            ),
            (crate::server::RequestCode::Unknown, u32::MAX),
        ] {
            assert_eq!(u32::from(code), expected);
            let bytes = bincode::serde::encode_to_vec(
                request(u32::from(code), 300_u32),
                bincode::config::standard(),
            )
            .unwrap();
            assert_eq!(bytes.get(..4).unwrap(), expected.to_le_bytes());
            assert_eq!(bytes.get(4..).unwrap(), &[251, 44, 1]);
        }
    }
}

#[cfg(test)]
mod framing_tests {
    #[tokio::test]
    async fn independent_header_and_body_bytes() {
        use oinq::frame::{FrameLimit, FramedWriter};
        let mut writer = FramedWriter::new(Vec::new(), FrameLimit::new(1024).unwrap());
        writer.start(super::request(109, 300_u32)).unwrap();
        writer.flush().await.unwrap();
        assert_eq!(writer.into_inner(), [0, 0, 0, 7, 109, 0, 0, 0, 251, 44, 1]);
    }
}
