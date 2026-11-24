use std::{collections::HashSet, io};

use serde::{Serialize, de::DeserializeOwned};

use super::Connection;
use crate::{
    server,
    types::{
        DaiCursors, DaiExtractorConfig, DaiObservationBatch, DaiRangeDay, DaiRangeGrant,
        DaiRangeLate, DaiRangeMark, DaiRangeUnit, DaiStoreAck, DataSource, DataSourceKey,
        DetectorStatusReport, HostNetworkGroup, NetworkListItem, ReportedRunState,
        TimeSeriesGenerationPolicy,
    },
    unary_request,
};

/// The client API.
impl Connection {
    /// Reports the final result of a customer-data deletion request.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the report.
    pub async fn report_customer_data_deletion(
        &self,
        report: &crate::types::CustomerDataDeletionReport,
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::ReportCustomerDataDeletion,
            report,
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Uploads the model a run produced.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the upload.
    pub async fn upload_run_model(&self, run_id: u32, model: &[u8]) -> io::Result<()> {
        let res: Result<(), String> =
            request(self, server::RequestCode::UploadRunModel, (run_id, model)).await?;
        res.map_err(io::Error::other)
    }

    /// Reports the state of a run, with the reason for it if any.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the report.
    pub async fn report_run(
        &self,
        run_id: u32,
        state: ReportedRunState,
        reason: Option<&str>,
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::ReportRun,
            (run_id, state, reason),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Reports the identifiers of the runs the engine still has.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the report.
    pub async fn report_active_runs(&self, run_ids: &[u32]) -> io::Result<()> {
        let res: Result<(), String> =
            request(self, server::RequestCode::ReportActiveRuns, run_ids).await?;
        res.map_err(io::Error::other)
    }

    /// Reports the status of a detector.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the report.
    pub async fn report_detector_status(&self, report: &DetectorStatusReport) -> io::Result<()> {
        let res: Result<(), String> =
            request(self, server::RequestCode::ReportDetectorStatus, report).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the configuration from the server.
    ///
    /// The format of the configuration is up to the caller to interpret.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_config(&self) -> io::Result<String> {
        let res: Result<String, String> = request(self, server::RequestCode::GetConfig, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the allowlist entries from the server, in the order the server
    /// sent them.
    ///
    /// Both the protocol version this connection advertised and the server's
    /// handshake reply must be `0.50.0` or later: a `0.49.0` payload can decode
    /// as a different item list (see [`NetworkListItem`]). Otherwise nothing
    /// is sent.
    ///
    /// # Errors
    ///
    /// Returns an error of kind [`io::ErrorKind::Unsupported`] if either
    /// handshake version is earlier than `0.50.0`, and an error if the request
    /// fails or the response is invalid.
    pub async fn get_allowlist(&self) -> io::Result<Vec<NetworkListItem>> {
        self.check_network_lists()?;
        let res: Result<Vec<NetworkListItem>, String> =
            request_exact(self, server::RequestCode::GetAllowlist, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the blocklist entries from the server, in the order the server
    /// sent them.
    ///
    /// Both the protocol version this connection advertised and the server's
    /// handshake reply must be `0.50.0` or later: a `0.49.0` payload can decode
    /// as a different item list (see [`NetworkListItem`]). Otherwise nothing
    /// is sent.
    ///
    /// # Errors
    ///
    /// Returns an error of kind [`io::ErrorKind::Unsupported`] if either
    /// handshake version is earlier than `0.50.0`, and an error if the request
    /// fails or the response is invalid.
    pub async fn get_blocklist(&self) -> io::Result<Vec<NetworkListItem>> {
        self.check_network_lists()?;
        let res: Result<Vec<NetworkListItem>, String> =
            request_exact(self, server::RequestCode::GetBlocklist, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches a data source from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_data_source(&self, key: &DataSourceKey<'_>) -> io::Result<DataSource> {
        let res: Result<Option<DataSource>, String> =
            request(self, server::RequestCode::GetDataSource, key).await?;
        res.map_err(io::Error::other)
            .and_then(|res| res.ok_or_else(|| io::Error::from(io::ErrorKind::NotFound)))
    }

    /// Fetches an indicator from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_indicator(&self, name: &str) -> io::Result<HashSet<Vec<String>>> {
        let res: Result<HashSet<Vec<String>>, String> =
            request(self, server::RequestCode::GetIndicator, name).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the list of internal networks from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_internal_network_list(&self) -> io::Result<HostNetworkGroup> {
        let res: Result<HostNetworkGroup, String> =
            request(self, server::RequestCode::GetInternalNetworkList, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the patterns from the label database.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_labeldb_patterns(
        &self,
        labeldbs: &[(&str, &str)],
    ) -> io::Result<Vec<(String, Option<crate::types::LabelDb>)>> {
        let res: Result<Vec<(String, Option<crate::types::LabelDb>)>, String> =
            request(self, server::RequestCode::GetLabelDbPatterns, labeldbs).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the list of Tor exit nodes from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_tor_exit_node_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTorExitNodeList, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the list of trusted domains from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_trusted_domain_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTrustedDomainList, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the list of trusted user agents from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_trusted_user_agent_list(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetTrustedUserAgentList, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the list of time-series generation policies from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_time_series_generation_policy_list(
        &self,
    ) -> io::Result<Vec<TimeSeriesGenerationPolicy>> {
        let res: Result<Vec<TimeSeriesGenerationPolicy>, String> = request(
            self,
            server::RequestCode::GetTimeSeriesGenerationPolicyList,
            (),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the pretrained model from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_pretrained_model(&self, name: &str) -> io::Result<Vec<u8>> {
        let res: Result<Vec<u8>, String> =
            request(self, server::RequestCode::GetPretrainedModel, name).await?;
        res.map_err(io::Error::other)
    }

    /// Obtains a new certificate from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn renew_certificate(&self) -> io::Result<(String, String)> {
        let res: Result<(String, String), String> =
            request(self, server::RequestCode::RenewCertificate, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches a model from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_model(&self, name: &str) -> io::Result<Vec<u8>> {
        let res: Result<Vec<u8>, String> =
            request(self, server::RequestCode::GetModel, name).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the list of model names from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_model_names(&self) -> io::Result<Vec<String>> {
        let res: Result<Vec<String>, String> =
            request(self, server::RequestCode::GetModelNames, ()).await?;
        res.map_err(io::Error::other)
    }

    /// Inserts column statistics into the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn insert_column_statistics(
        &self,
        statistics: &[crate::types::ColumnStatisticsUpdate],
        model_id: u32,
        batch_ts: i64,
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::InsertColumnStatistics,
            &(statistics, model_id, batch_ts),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Inserts a model into the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn insert_model(&self, model: &[u8]) -> io::Result<u32> {
        let res: Result<u32, String> =
            request(self, server::RequestCode::InsertModel, model).await?;
        res.map_err(io::Error::other)
    }

    /// Inserts time series data into the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn insert_time_series(
        &self,
        time_series: &[crate::types::TimeSeriesUpdate],
        model_id: u32,
        batch_ts: i64,
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::InsertTimeSeries,
            &(time_series, model_id, batch_ts),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Removes a model from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn remove_model(&self, name: &str) -> io::Result<()> {
        let res: Result<(), String> = request(self, server::RequestCode::RemoveModel, name).await?;
        res.map_err(io::Error::other)
    }

    /// Updates clusters on the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn update_clusters(
        &self,
        input: &[crate::types::UpdateClusterRequest],
        model_id: u32,
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::UpdateClusters,
            &(input, model_id),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Updates a model on the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn update_model(&self, model: &[u8]) -> io::Result<u32> {
        let res: Result<u32, String> =
            request(self, server::RequestCode::UpdateModel, model).await?;
        res.map_err(io::Error::other)
    }

    /// Updates outliers on the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn update_outliers(
        &self,
        outliers: &[crate::types::OutlierInfo],
        model_id: u32,
        timestamp: i64,
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::UpdateOutliers,
            &(outliers, model_id, timestamp),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Sends the detection events `model_id` produced in `round` to the
    /// server.
    ///
    /// The events are sent as given; this does not call
    /// [`DetectionEvent::validate`](crate::types::DetectionEvent::validate).
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn insert_detection_events(
        &self,
        model_id: u32,
        round: u32,
        events: &[crate::types::DetectionEvent],
    ) -> io::Result<()> {
        let res: Result<(), String> = request(
            self,
            server::RequestCode::InsertDetectionEvents,
            &(model_id, round, events),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Inserts a data source into the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn insert_data_source(
        &self,
        data_source: &crate::types::DataSource,
    ) -> io::Result<u32> {
        let res: Result<u32, String> =
            request(self, server::RequestCode::InsertDataSource, data_source).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches outliers from the server.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails or the response is invalid.
    pub async fn get_outliers(
        &self,
        model_id: u32,
        timestamp: i64,
    ) -> io::Result<Vec<(String, Vec<i64>)>> {
        let res: Result<Vec<(String, Vec<i64>)>, String> = request(
            self,
            server::RequestCode::GetOutliers,
            &(model_id, timestamp),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the DAI extractor configuration for `sensors`.
    ///
    /// A list that is exactly `["all"]` stands for every sensor that belongs
    /// to a customer. Otherwise the answer covers only the named sensors that
    /// belong to a customer; other names are left out, not reported as
    /// errors. See [`DaiExtractorConfig`] for what the answer holds.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the request; a server that does not serve it answers
    /// `not supported`.
    pub async fn get_dai_extractor_config(
        &self,
        sensors: &[String],
    ) -> io::Result<DaiExtractorConfig> {
        let res: Result<DaiExtractorConfig, String> =
            request(self, server::RequestCode::GetDaiExtractorConfig, sensors).await?;
        res.map_err(io::Error::other)
    }

    /// Fetches the DAI read cursors for `sensors`.
    ///
    /// The sensor list is read as for
    /// [`get_dai_extractor_config`](Self::get_dai_extractor_config). See
    /// [`DaiCursors`] for what the answer holds.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the request; a server that does not serve it answers
    /// `not supported`.
    pub async fn get_dai_cursors(&self, sensors: &[String]) -> io::Result<DaiCursors> {
        let res: Result<DaiCursors, String> =
            request(self, server::RequestCode::GetDaiCursors, sensors).await?;
        res.map_err(io::Error::other)
    }

    /// Sends one part of one send of the observations of a slot.
    ///
    /// See [`DaiObservationBatch`] for the rules the server applies to it and
    /// [`DaiStoreAck`] for the answers.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the request; a server that does not serve it answers
    /// `not supported`.
    pub async fn send_dai_observations(
        &self,
        batch: &DaiObservationBatch,
    ) -> io::Result<DaiStoreAck> {
        let res: Result<DaiStoreAck, String> =
            request(self, server::RequestCode::SendDaiObservations, batch).await?;
        res.map_err(io::Error::other)
    }

    /// Starts a round of range day `unit`, holding `restore_generation`.
    ///
    /// A grant raises the unit's version and grants a lease with a fresh
    /// random lease token. See [`DaiRangeGrant`] for the answers.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the request; a server that does not serve it answers
    /// `not supported`.
    pub async fn begin_dai_range_day(
        &self,
        unit: &DaiRangeUnit,
        restore_generation: u64,
    ) -> io::Result<DaiRangeGrant> {
        let res: Result<DaiRangeGrant, String> = request(
            self,
            server::RequestCode::BeginDaiRangeDay,
            (unit, restore_generation),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Renews the lease `lease_token` on range day `unit`.
    ///
    /// Returns the new lease end, in nanoseconds since the UNIX epoch, or
    /// `None` when the token is no longer the unit's current one; the round
    /// then stops.
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the request; a server that does not serve it answers
    /// `not supported`.
    pub async fn renew_dai_range_day(
        &self,
        unit: &DaiRangeUnit,
        lease_token: u64,
    ) -> io::Result<Option<i64>> {
        let res: Result<Option<i64>, String> = request(
            self,
            server::RequestCode::RenewDaiRangeDay,
            (unit, lease_token),
        )
        .await?;
        res.map_err(io::Error::other)
    }

    /// Sends the counts of a range day.
    ///
    /// The server answers [`DaiStoreAck::Stored`] also for a result from a
    /// superseded lease, which it discards; see [`DaiRangeDay`].
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the request; a server that does not serve it answers
    /// `not supported`.
    pub async fn send_dai_range_day(&self, day: &DaiRangeDay) -> io::Result<DaiStoreAck> {
        let res: Result<DaiStoreAck, String> =
            request(self, server::RequestCode::SendDaiRangeDay, day).await?;
        res.map_err(io::Error::other)
    }

    /// Reports late range days and subnets, and returns the marks the server
    /// assigned to `late_days`.
    ///
    /// `late_subnets` are recorded without a mark; see [`DaiRangeLate`].
    ///
    /// # Errors
    ///
    /// Returns an error if the request fails, the response is invalid, or the
    /// server rejects the request; a server that does not serve it answers
    /// `not supported`. A rejection (for example when the restore generation
    /// differs) means nothing was recorded: call
    /// [`get_dai_cursors`](Self::get_dai_cursors) again before reporting.
    pub async fn report_dai_range_late(
        &self,
        late: &DaiRangeLate,
    ) -> io::Result<Vec<DaiRangeMark>> {
        let res: Result<Vec<DaiRangeMark>, String> =
            request(self, server::RequestCode::ReportDaiRangeLate, late).await?;
        res.map_err(io::Error::other)
    }
}

async fn request<I, O>(conn: &Connection, code: server::RequestCode, input: I) -> io::Result<O>
where
    I: Serialize,
    O: DeserializeOwned,
{
    let (mut send, mut recv) = conn.open_bi().await?;
    unary_request(&mut send, &mut recv, u32::from(code), input).await
}

/// Sends a request like [`request`] and rejects a response with bytes left
/// over after it; see `legacy_transport::decode_exact`.
async fn request_exact<I, O>(
    conn: &Connection,
    code: server::RequestCode,
    input: I,
) -> io::Result<O>
where
    I: Serialize,
    O: DeserializeOwned,
{
    let (mut send, mut recv) = conn.open_bi().await?;
    crate::legacy_transport::unary_exact(&mut send, &mut recv, u32::from(code), input).await
}

#[cfg(all(test, feature = "server"))]
mod tests {
    #![allow(clippy::unwrap_used)]

    use crate::{
        server::handle,
        test::{
            ACTIVE_RUN_IDS, REJECTED_DETECTOR_ID, REJECTED_RUN_ID, RUN_ID, RUN_MODEL, RUN_REPORTS,
            TEST_ENV, TestServerHandler, detector_status_reports,
        },
        types::{
            CustomerDataDeletionOutcome, CustomerDataDeletionReport, CustomerDataDeletionReporter,
            DataSourceKey, DetectorState, DetectorStatusReport, RawEventKind, ReportedRunState,
        },
    };

    async fn run_test<F, Fut>(client_logic: F)
    where
        F: FnOnce(crate::client::Connection) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        run_test_with(TestServerHandler, client_logic).await;
    }

    /// Runs `client_logic` against a server that serves one request stream
    /// with `handler`.
    async fn run_test_with<H, F, Fut>(mut handler: H, client_logic: F)
    where
        H: crate::server::Handler + Send + Sync + 'static,
        F: FnOnce(crate::client::Connection) -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn) = test_env.setup().await;

        let handler_conn = server_conn.clone();
        let server_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.as_quinn().accept_bi().await.unwrap();
            handle(&mut handler, &mut send, &mut recv, "test-peer").await?;
            Ok(()) as std::io::Result<()>
        });

        client_logic(client_conn).await;

        let server_res = server_handle.await.unwrap();
        match server_res {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                // Connection closed after client finished - this is expected
            }
            Err(e) => panic!("Unexpected server error: {e:?}"),
        }

        test_env.teardown(&server_conn);
    }

    #[tokio::test]
    async fn get_data_source() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_data_source(&DataSourceKey::Id(5)).await;
            assert!(client_res.is_ok());
            let received_data_source = client_res.unwrap();
            assert_eq!(received_data_source.name, "name5");
        })
        .await;
    }

    #[tokio::test]
    async fn report_customer_data_deletion_returns_handler_ok() {
        run_test(|client_conn| async move {
            let report = CustomerDataDeletionReport {
                id: 42,
                host_fqdn: "sensor.example.test".to_string(),
                completed_at: Some(1_700_000_100),
                reporter: CustomerDataDeletionReporter::Sensor,
                outcome: CustomerDataDeletionOutcome::Succeeded,
            };
            assert!(
                client_conn
                    .report_customer_data_deletion(&report)
                    .await
                    .is_ok()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn report_customer_data_deletion_converts_handler_error() {
        run_test(|client_conn| async move {
            let report = CustomerDataDeletionReport {
                id: 43,
                host_fqdn: "reject.example.test".to_string(),
                completed_at: None,
                reporter: CustomerDataDeletionReporter::SemiSupervised,
                outcome: CustomerDataDeletionOutcome::Failed("deletion failed".to_string()),
            };
            let error = client_conn
                .report_customer_data_deletion(&report)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Other);
            assert_eq!(error.to_string(), "report rejected");
        })
        .await;
    }

    #[tokio::test]
    async fn upload_run_model_returns_handler_ok() {
        run_test(|client_conn| async move {
            assert!(
                client_conn
                    .upload_run_model(RUN_ID, RUN_MODEL)
                    .await
                    .is_ok()
            );
        })
        .await;
    }

    #[tokio::test]
    async fn upload_run_model_converts_handler_error() {
        run_test(|client_conn| async move {
            let error = client_conn
                .upload_run_model(REJECTED_RUN_ID, RUN_MODEL)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Other);
            assert_eq!(error.to_string(), "report rejected");
        })
        .await;
    }

    #[tokio::test]
    async fn report_run_returns_handler_ok() {
        for &(run_id, state, reason) in RUN_REPORTS {
            run_test(|client_conn| async move {
                assert!(
                    client_conn.report_run(run_id, state, reason).await.is_ok(),
                    "run report ({run_id}, {state:?}, {reason:?}) should arrive intact"
                );
            })
            .await;
        }
    }

    #[tokio::test]
    async fn report_run_converts_handler_error() {
        run_test(|client_conn| async move {
            let error = client_conn
                .report_run(REJECTED_RUN_ID, ReportedRunState::Failed, Some("failed"))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Other);
            assert_eq!(error.to_string(), "report rejected");
        })
        .await;
    }

    #[tokio::test]
    async fn report_active_runs_returns_handler_ok() {
        run_test(|client_conn| async move {
            assert!(client_conn.report_active_runs(ACTIVE_RUN_IDS).await.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn report_active_runs_converts_handler_error() {
        run_test(|client_conn| async move {
            let error = client_conn
                .report_active_runs(&[RUN_ID, REJECTED_RUN_ID])
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Other);
            assert_eq!(error.to_string(), "report rejected");
        })
        .await;
    }

    #[tokio::test]
    async fn report_detector_status_returns_handler_ok() {
        for report in detector_status_reports() {
            run_test(|client_conn| async move {
                assert!(
                    client_conn.report_detector_status(&report).await.is_ok(),
                    "detector status report {report:?} should arrive intact"
                );
            })
            .await;
        }
    }

    #[tokio::test]
    async fn report_detector_status_converts_handler_error() {
        run_test(|client_conn| async move {
            let report = DetectorStatusReport {
                detector_id: REJECTED_DETECTOR_ID,
                state: DetectorState::Running,
                finished_at: None,
                outcome: None,
                reason: None,
                events: 0,
                sources: Vec::new(),
                detection_models: Vec::new(),
                excluded: Vec::new(),
            };
            let error = client_conn
                .report_detector_status(&report)
                .await
                .unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::Other);
            assert_eq!(error.to_string(), "report rejected");
        })
        .await;
    }

    #[tokio::test]
    async fn get_labeldb_patterns() {
        run_test(|client_conn| async move {
            let db_names = vec![("db1", "1.0.0"), ("db2", "2.0.0")];
            let client_res = client_conn.get_labeldb_patterns(&db_names).await;
            assert!(client_res.is_ok());
            let received_patterns = client_res.unwrap();
            assert_eq!(received_patterns.len(), db_names.len());
            assert_eq!(received_patterns[0].0, "db1");
            assert!(received_patterns[0].1.is_some());
            assert_eq!(received_patterns[1].0, "db2");
            assert!(received_patterns[1].1.is_none());
        })
        .await;
    }

    #[tokio::test]
    async fn get_config() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_config().await;
            assert!(client_res.is_ok());
            let received_config = client_res.unwrap();
            assert_eq!(received_config, "test-config");
        })
        .await;
    }

    #[tokio::test]
    async fn get_allowlist() {
        run_test(|client_conn| async move {
            let received_allowlist = client_conn.get_allowlist().await.unwrap();
            assert_eq!(received_allowlist, crate::test::network_list_items());
        })
        .await;
    }

    #[tokio::test]
    async fn get_blocklist() {
        run_test(|client_conn| async move {
            let received_blocklist = client_conn.get_blocklist().await.unwrap();
            let mut expected = crate::test::network_list_items();
            expected.reverse();
            assert_eq!(received_blocklist, expected);
        })
        .await;
    }

    /// A `0.49.0` server's allowlist or blocklist reply, a
    /// `HostNetworkGroup` with no explicit hosts but other entries, is
    /// refused rather than read as an empty item list.
    #[tokio::test]
    async fn list_pull_rejects_legacy_reply() {
        use std::net::{IpAddr, Ipv4Addr};

        use crate::{
            legacy_transport::frame,
            types::{HostNetworkGroup, NetworkListItem},
        };

        let group = HostNetworkGroup {
            hosts: Vec::new(),
            networks: vec!["192.0.2.0/24".parse().unwrap()],
            ip_ranges: vec![
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))
                    ..=IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
            ],
        };
        let reply =
            bincode::serde::encode_to_vec(Ok::<_, String>(group), bincode::config::standard())
                .unwrap();
        let (prefix, _) = bincode::serde::decode_from_slice::<
            Result<Vec<NetworkListItem>, String>,
            _,
        >(&reply, bincode::config::standard())
        .expect("a prefix decode reads the legacy reply");
        assert_eq!(
            prefix,
            Ok(Vec::new()),
            "a prefix decode reads an empty list"
        );

        let test_env = TEST_ENV.lock().await;
        for pull_blocklist in [false, true] {
            let (server_conn, client_conn) = test_env.setup().await;
            let server_reply = reply.clone();
            let handler_conn = server_conn.clone();
            let server_handle = tokio::spawn(async move {
                let (mut send, mut recv) = handler_conn.as_quinn().accept_bi().await.unwrap();
                let mut request = Vec::new();
                frame::recv_raw(&mut recv, &mut request).await.unwrap();
                frame::send_raw(&mut send, &server_reply).await.unwrap();
                send.finish().unwrap();
                let _ = send.stopped().await;
            });

            let res = if pull_blocklist {
                client_conn.get_blocklist().await
            } else {
                client_conn.get_allowlist().await
            };
            assert_eq!(
                res.expect_err("the legacy reply is refused").kind(),
                std::io::ErrorKind::InvalidData
            );

            server_handle.await.unwrap();
            test_env.teardown(&server_conn);
        }
    }

    /// A connection that advertised `0.49.0` refuses its allowlist and
    /// blocklist pulls before sending them: a server reply in the `0.49.0`
    /// shape holding one IPv4 host is also a complete item list, which
    /// full-frame decoding cannot refuse.
    #[tokio::test]
    async fn list_pull_refuses_an_agent_advertising_0_49_0() {
        use std::net::{IpAddr, Ipv4Addr};

        use crate::types::{HostNetworkGroup, NetworkListItem};

        let group = HostNetworkGroup {
            hosts: vec![IpAddr::V4(Ipv4Addr::new(2, b'x', b'y', 0))],
            networks: Vec::new(),
            ip_ranges: Vec::new(),
        };
        let reply =
            bincode::serde::encode_to_vec(Ok::<_, String>(group), bincode::config::standard())
                .unwrap();
        let misread: Result<Vec<NetworkListItem>, String> =
            crate::legacy_transport::decode_exact(&reply).unwrap();
        assert_eq!(
            misread,
            Ok(vec![NetworkListItem {
                id: 0,
                name: "xy".into(),
                group: HostNetworkGroup::default(),
            }]),
            "the legacy reply decodes in full as a different list"
        );

        let test_env = TEST_ENV.lock().await;
        let (server_conn, client_conn, _) =
            test_env.setup_advertising("0.49.0", |_builder| {}).await;
        for res in [
            client_conn.get_allowlist().await,
            client_conn.get_blocklist().await,
        ] {
            let error = res.expect_err("the pull is refused");
            assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
            assert_eq!(
                error.to_string(),
                "protocol 0.49.0 is incompatible with >=0.50.0"
            );
        }

        // Nothing was sent: the first request the server receives is the
        // next one.
        let handler_conn = server_conn.clone();
        let server_handle = tokio::spawn(async move {
            let (mut send, mut recv) = handler_conn.as_quinn().accept_bi().await.unwrap();
            let mut request = Vec::new();
            crate::legacy_transport::frame::recv_raw(&mut recv, &mut request)
                .await
                .unwrap();
            let reply =
                bincode::serde::encode_to_vec(Ok::<_, String>("cfg"), bincode::config::standard())
                    .unwrap();
            crate::legacy_transport::frame::send_raw(&mut send, &reply)
                .await
                .unwrap();
            send.finish().unwrap();
            let _ = send.stopped().await;
            request
        });
        assert_eq!(client_conn.get_config().await.unwrap(), "cfg");
        let request = server_handle.await.unwrap();
        assert_eq!(
            request.first_chunk::<4>().copied().map(u32::from_le_bytes),
            Some(u32::from(crate::server::RequestCode::GetConfig))
        );
        test_env.teardown(&server_conn);
    }

    #[tokio::test]
    async fn get_indicator() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_indicator("test-indicator").await;
            assert!(client_res.is_ok());
            let received_indicator = client_res.unwrap();
            assert_eq!(received_indicator.len(), 2);
        })
        .await;
    }

    #[tokio::test]
    async fn get_internal_network_list() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_internal_network_list().await;
            assert!(client_res.is_ok());
            let received_list = client_res.unwrap();
            assert_eq!(received_list.hosts.len(), 1);
        })
        .await;
    }

    #[tokio::test]
    async fn get_tor_exit_node_list() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_tor_exit_node_list().await;
            assert!(client_res.is_ok());
            let received_list = client_res.unwrap();
            assert_eq!(received_list.len(), 2);
            assert_eq!(received_list[0], "192.168.1.10");
            assert_eq!(received_list[1], "192.168.1.11");
        })
        .await;
    }

    #[tokio::test]
    async fn get_trusted_domain_list() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_trusted_domain_list().await;
            assert!(client_res.is_ok());
            let received_list = client_res.unwrap();
            assert_eq!(received_list.len(), 2);
            assert_eq!(received_list[0], "trusted1.com");
            assert_eq!(received_list[1], "trusted2.com");
        })
        .await;
    }

    #[tokio::test]
    async fn get_trusted_user_agent_list() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_trusted_user_agent_list().await;
            assert!(client_res.is_ok());
            let received_list = client_res.unwrap();
            assert_eq!(received_list.len(), 2);
            assert_eq!(received_list[0], "Mozilla/5.0 (trusted)");
            assert_eq!(received_list[1], "Chrome/test");
        })
        .await;
    }

    #[tokio::test]
    async fn get_time_series_generation_policy_list() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_time_series_generation_policy_list().await;
            assert!(client_res.is_ok());
            let policies = client_res.unwrap();
            assert_eq!(policies.len(), 1);
            assert_eq!(policies[0].id, 1);
            assert_eq!(policies[0].raw_event_kind, RawEventKind::Dns);
            assert_eq!(policies[0].sensors, ["node1"]);
            assert_eq!(policies[0].time_series_type, None);
        })
        .await;
    }

    #[tokio::test]
    async fn get_pretrained_model() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_pretrained_model("test-model").await;
            assert!(client_res.is_ok());
            let received_model = client_res.unwrap();
            assert_eq!(received_model, vec![0x01, 0x02, 0x03, 0x04]);
        })
        .await;
    }

    #[tokio::test]
    async fn renew_certificate() {
        run_test(|client_conn| async move {
            let client_res = client_conn.renew_certificate().await;
            assert!(client_res.is_ok());
            let (new_cert, new_key) = client_res.unwrap();
            assert_eq!(new_cert, "new-cert");
            assert_eq!(new_key, "new-key");
        })
        .await;
    }

    #[tokio::test]
    async fn get_model() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_model("test-model").await;
            assert!(client_res.is_ok());
            let model = client_res.unwrap();
            assert_eq!(model, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
        })
        .await;
    }

    #[tokio::test]
    async fn get_model_names() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_model_names().await;
            assert!(client_res.is_ok());
            let names = client_res.unwrap();
            assert_eq!(names, vec!["model1", "model2", "model3"]);
        })
        .await;
    }

    #[tokio::test]
    async fn insert_column_statistics() {
        run_test(|client_conn| async move {
            let data = vec![crate::types::ColumnStatisticsUpdate {
                cluster_id: 1,
                column_statistics: vec![],
            }];
            let client_res = client_conn.insert_column_statistics(&data, 1, 1000).await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn insert_model() {
        run_test(|client_conn| async move {
            let model_bytes = vec![0x01, 0x02, 0x03];
            let client_res = client_conn.insert_model(&model_bytes).await;
            assert!(client_res.is_ok());
            assert_eq!(client_res.unwrap(), 42);
        })
        .await;
    }

    #[tokio::test]
    async fn insert_time_series() {
        run_test(|client_conn| async move {
            let data = vec![crate::types::TimeSeriesUpdate {
                cluster_id: 1,
                time_series: vec![],
            }];
            let client_res = client_conn.insert_time_series(&data, 1, 1000).await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn remove_model() {
        run_test(|client_conn| async move {
            let client_res = client_conn.remove_model("test-model").await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn update_clusters() {
        run_test(|client_conn| async move {
            let data = vec![crate::types::UpdateClusterRequest {
                cluster_id: 1,
                detector_id: 1,
                signature: "test-sig".to_string(),
                score: Some(0.5),
                size: 100,
                event_ids: vec![],
                status_id: 1,
                labels: None,
            }];
            let client_res = client_conn.update_clusters(&data, 1).await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn update_model() {
        run_test(|client_conn| async move {
            let model_bytes = vec![0x01, 0x02, 0x03];
            let client_res = client_conn.update_model(&model_bytes).await;
            assert!(client_res.is_ok());
            assert_eq!(client_res.unwrap(), 55);
        })
        .await;
    }

    #[tokio::test]
    async fn update_outliers() {
        run_test(|client_conn| async move {
            let data = vec![crate::types::OutlierInfo {
                id: 1,
                rank: 1,
                distance: 0.5,
                sensor: "test-sensor".to_string(),
            }];
            let client_res = client_conn.update_outliers(&data, 1, 1000).await;
            assert!(client_res.is_ok());
        })
        .await;
    }

    #[tokio::test]
    async fn insert_detection_events() {
        run_test(|client_conn| async move {
            use crate::test::{DETECTION_EVENTS_MODEL_ID, DETECTION_EVENTS_ROUND};

            // The handler accepts only this model ID, round and batch, whole
            // and in order, including the event that fails `validate`.
            let events = crate::test::detection_events();
            assert!(
                events[crate::test::INVALID_DETECTION_EVENT]
                    .validate()
                    .is_err()
            );
            client_conn
                .insert_detection_events(DETECTION_EVENTS_MODEL_ID, DETECTION_EVENTS_ROUND, &events)
                .await
                .unwrap();
        })
        .await;
    }

    #[tokio::test]
    async fn insert_detection_events_checks_every_argument() {
        use crate::test::{DETECTION_EVENTS_MODEL_ID, DETECTION_EVENTS_ROUND};

        // The handler refuses a request that changes any one argument, so a
        // swapped, dropped, truncated or reordered argument cannot pass.
        let events = crate::test::detection_events();
        let mut truncated = events.clone();
        truncated.pop();
        let mut reordered = events.clone();
        reordered.swap(0, 1);
        let cases = [
            (DETECTION_EVENTS_ROUND, DETECTION_EVENTS_MODEL_ID, events),
            (
                DETECTION_EVENTS_MODEL_ID,
                DETECTION_EVENTS_ROUND,
                Vec::new(),
            ),
            (DETECTION_EVENTS_MODEL_ID, DETECTION_EVENTS_ROUND, truncated),
            (DETECTION_EVENTS_MODEL_ID, DETECTION_EVENTS_ROUND, reordered),
        ];
        for (model_id, round, events) in cases {
            run_test(|client_conn| async move {
                let error = client_conn
                    .insert_detection_events(model_id, round, &events)
                    .await
                    .unwrap_err();
                assert_eq!(error.kind(), std::io::ErrorKind::Other);
                assert!(
                    error
                        .to_string()
                        .starts_with("unexpected detection event request"),
                    "{error}"
                );
            })
            .await;
        }
    }

    #[tokio::test]
    async fn insert_data_source() {
        run_test(|client_conn| async move {
            let data = crate::types::DataSource {
                id: 0,
                name: "test-source".to_string(),
                server_name: "test-server".to_string(),
                address: "127.0.0.1:8080".parse().unwrap(),
                data_type: crate::types::DataType::Log,
                source: "test".to_string(),
                kind: None,
                description: "test description".to_string(),
            };
            let client_res = client_conn.insert_data_source(&data).await;
            assert!(client_res.is_ok());
            assert_eq!(client_res.unwrap(), 123);
        })
        .await;
    }

    #[tokio::test]
    async fn get_outliers() {
        run_test(|client_conn| async move {
            let client_res = client_conn.get_outliers(10, 1000).await;
            assert!(client_res.is_ok());
            let outliers = client_res.unwrap();
            assert_eq!(outliers.len(), 2);
            assert_eq!(outliers[0].0, "sensor1");
            assert_eq!(outliers[0].1, vec![1, 2, 3]);
            assert_eq!(outliers[1].0, "sensor2");
            assert_eq!(outliers[1].1, vec![4, 5, 6]);
        })
        .await;
    }

    /// A handler that overrides no DAI method.
    struct DefaultHandler;
    impl crate::server::Handler for DefaultHandler {}

    fn dai_handler() -> crate::test::DaiTestHandler {
        crate::test::DaiTestHandler { peer: "test-peer" }
    }

    fn assert_not_supported<T: std::fmt::Debug>(result: std::io::Result<T>) {
        let error = result.unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::Other);
        assert_eq!(error.to_string(), "not supported");
    }

    #[tokio::test]
    async fn get_dai_extractor_config_returns_handler_reply() {
        run_test_with(dai_handler(), |client_conn| async move {
            let config = client_conn
                .get_dai_extractor_config(&crate::test::dai_sensors())
                .await
                .unwrap();
            assert_eq!(config, crate::test::dai_extractor_config());
        })
        .await;
    }

    #[tokio::test]
    async fn get_dai_extractor_config_default_is_not_supported() {
        run_test_with(DefaultHandler, |client_conn| async move {
            assert_not_supported(
                client_conn
                    .get_dai_extractor_config(&["all".to_string()])
                    .await,
            );
        })
        .await;
    }

    #[tokio::test]
    async fn get_dai_cursors_returns_handler_reply() {
        run_test_with(dai_handler(), |client_conn| async move {
            let cursors = client_conn
                .get_dai_cursors(&crate::test::dai_sensors())
                .await
                .unwrap();
            assert_eq!(cursors, crate::test::dai_cursors());
        })
        .await;
    }

    #[tokio::test]
    async fn get_dai_cursors_default_is_not_supported() {
        run_test_with(DefaultHandler, |client_conn| async move {
            assert_not_supported(client_conn.get_dai_cursors(&["all".to_string()]).await);
        })
        .await;
    }

    #[tokio::test]
    async fn send_dai_observations_returns_handler_reply() {
        run_test_with(dai_handler(), |client_conn| async move {
            let batch = crate::test::dai_observation_batches().remove(0);
            let ack = client_conn.send_dai_observations(&batch).await.unwrap();
            assert_eq!(ack, crate::test::dai_store_acks().remove(1));
        })
        .await;
    }

    #[tokio::test]
    async fn send_dai_observations_default_is_not_supported() {
        run_test_with(DefaultHandler, |client_conn| async move {
            let batch = crate::test::dai_observation_batches().remove(0);
            assert_not_supported(client_conn.send_dai_observations(&batch).await);
        })
        .await;
    }

    #[tokio::test]
    async fn begin_dai_range_day_returns_handler_reply() {
        run_test_with(dai_handler(), |client_conn| async move {
            let grant = client_conn
                .begin_dai_range_day(&crate::test::dai_range_unit(), 5)
                .await
                .unwrap();
            assert_eq!(grant, crate::test::dai_range_grants().remove(0));
        })
        .await;
    }

    #[tokio::test]
    async fn begin_dai_range_day_default_is_not_supported() {
        run_test_with(DefaultHandler, |client_conn| async move {
            assert_not_supported(
                client_conn
                    .begin_dai_range_day(&crate::test::dai_range_unit(), 5)
                    .await,
            );
        })
        .await;
    }

    #[tokio::test]
    async fn renew_dai_range_day_returns_handler_reply() {
        run_test_with(dai_handler(), |client_conn| async move {
            let lease_end = client_conn
                .renew_dai_range_day(&crate::test::dai_range_unit(), 0x0bad_cafe_0bad_cafe)
                .await
                .unwrap();
            assert_eq!(lease_end, Some(crate::test::DAI_RENEWED_LEASE_END));
        })
        .await;
    }

    #[tokio::test]
    async fn renew_dai_range_day_default_is_not_supported() {
        run_test_with(DefaultHandler, |client_conn| async move {
            assert_not_supported(
                client_conn
                    .renew_dai_range_day(&crate::test::dai_range_unit(), 1)
                    .await,
            );
        })
        .await;
    }

    #[tokio::test]
    async fn send_dai_range_day_returns_handler_reply() {
        run_test_with(dai_handler(), |client_conn| async move {
            let day = crate::test::dai_range_days().remove(0);
            let ack = client_conn.send_dai_range_day(&day).await.unwrap();
            assert_eq!(ack, crate::test::dai_store_acks().remove(1));
        })
        .await;
    }

    #[tokio::test]
    async fn send_dai_range_day_default_is_not_supported() {
        run_test_with(DefaultHandler, |client_conn| async move {
            let day = crate::test::dai_range_days().remove(0);
            assert_not_supported(client_conn.send_dai_range_day(&day).await);
        })
        .await;
    }

    #[tokio::test]
    async fn report_dai_range_late_returns_handler_reply() {
        run_test_with(dai_handler(), |client_conn| async move {
            let marks = client_conn
                .report_dai_range_late(&crate::test::dai_range_late())
                .await
                .unwrap();
            assert_eq!(marks, crate::test::dai_range_marks());
        })
        .await;
    }

    #[tokio::test]
    async fn report_dai_range_late_default_is_not_supported() {
        run_test_with(DefaultHandler, |client_conn| async move {
            assert_not_supported(
                client_conn
                    .report_dai_range_late(&crate::test::dai_range_late())
                    .await,
            );
        })
        .await;
    }
}
