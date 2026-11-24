//! Request handler for the server.
//!
//! # `ProtocolErrorKind` integration
//!
//! Selected request paths in [`handle_authorized`] classify internal
//! errors with [`ProtocolErrorKind`](crate::ProtocolErrorKind) via
//! [`DispatchError`].  This is an **internal-only** taxonomy — it
//! does not change the on-wire error format.  Callers can recover
//! the classification from the returned `io::Error` with
//! [`ProtocolErrorKind::of_io_error`](crate::ProtocolErrorKind::of_io_error).
//!
//! Currently classified paths:
//!
//! - Authorization denials → [`Forbidden`](crate::ProtocolErrorKind::Forbidden)
//! - Unknown request codes → [`NotSupported`](crate::ProtocolErrorKind::NotSupported)
//! - Argument parse failures (representative handlers) →
//!   [`InvalidArgs`](crate::ProtocolErrorKind::InvalidArgs)
//!
//! Future handlers should follow the same pattern when adding
//! classification. When the project moves to surface
//! `ProtocolErrorKind` on the wire, prefer additive changes (new
//! optional fields or a parallel error envelope) to avoid breaking
//! existing clients.

use std::{collections::HashSet, io};

use num_enum::FromPrimitive;
use oinq::request::parse_args;

use super::{AUTHORIZATION_DENIED, RequestCode, UNKNOWN_REQUEST_CODE};
use crate::legacy_transport as oinq;
use crate::protocol_error::{DispatchError, ProtocolErrorKind};
use crate::types::{
    ColumnStatisticsUpdate, CustomerDataDeletionReport, DaiCursors, DaiExtractorConfig,
    DaiObservationBatch, DaiRangeDay, DaiRangeGrant, DaiRangeLate, DaiRangeMark, DaiRangeUnit,
    DaiStoreAck, DataSource, DataSourceKey, DetectionEvent, DetectorStatusReport,
    EngineExclusionReport, HostNetworkGroup, LabelDb, NetworkListItem, OutlierInfo,
    ReportedRunState, TimeSeriesGenerationPolicy, TimeSeriesUpdate, UpdateClusterRequest,
};

/// A request handler that can handle a request to the server.
#[async_trait::async_trait]
pub trait Handler {
    async fn report_customer_data_deletion(
        &self,
        _report: &CustomerDataDeletionReport,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    /// Answers request 32, the exclusion-list entries in the order to send them.
    ///
    /// The session layer's request stream calls this only for an agent that
    /// advertised protocol `0.50.0` or later. The legacy dispatchers hold no
    /// handshake version, so their caller checks it; see [`NetworkListItem`].
    async fn get_exclusion_list(&self, _peer: &str) -> Result<Vec<NetworkListItem>, String> {
        Err("not supported".to_string())
    }

    /// Answers request 33, the watchlist entries in the order to send them.
    ///
    /// The session layer's request stream calls this only for an agent that
    /// advertised protocol `0.50.0` or later. The legacy dispatchers hold no
    /// handshake version, so their caller checks it; see [`NetworkListItem`].
    async fn get_watchlist(&self, _peer: &str) -> Result<Vec<NetworkListItem>, String> {
        Err("not supported".to_string())
    }

    async fn get_config(&self, _peer: &str) -> Result<String, String> {
        Err("not supported".to_string())
    }

    async fn get_data_source(
        &self,
        _key: &DataSourceKey<'_>,
    ) -> Result<Option<DataSource>, String> {
        Err("not supported".to_string())
    }

    async fn get_indicator(&self, _name: &str) -> Result<HashSet<Vec<String>>, String> {
        Err("not supported".to_string())
    }

    async fn get_internal_network_list(&self, _peer: &str) -> Result<HostNetworkGroup, String> {
        Err("not supported".to_string())
    }

    async fn get_model(&self, _name: &str) -> Result<Vec<u8>, String> {
        Err("not supported".to_string())
    }

    async fn get_model_names(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn get_outliers(
        &self,
        _model_id: u32,
        _timestamp: i64,
    ) -> Result<Vec<(String, Vec<i64>)>, String> {
        Err("not supported".to_string())
    }

    async fn get_pretrained_model(&self, _name: &str) -> Result<Vec<u8>, String> {
        Err("not supported".to_string())
    }

    async fn get_time_series_generation_policy_list(
        &self,
        _peer: &str,
    ) -> Result<Vec<TimeSeriesGenerationPolicy>, String> {
        Err("not supported".to_string())
    }

    async fn get_labeldb_patterns(
        &self,
        _db_names: &[(&str, &str)],
    ) -> Result<Vec<(String, Option<LabelDb>)>, String> {
        Err("not supported".to_string())
    }

    async fn get_tor_exit_node_list(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn get_trusted_domain_list(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn get_trusted_user_agent_list(&self) -> Result<Vec<String>, String> {
        Err("not supported".to_string())
    }

    async fn insert_column_statistics(
        &self,
        _statistics: &[ColumnStatisticsUpdate],
        _model_id: u32,
        _batch_ts: i64,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn insert_data_source(&self, _data_source: &DataSource) -> Result<u32, String> {
        Err("not supported".to_string())
    }

    /// Handles request 13, the detection events of `model_id` in `round`.
    ///
    /// `events` holds every decodable event of the request, in order, as
    /// decoded: the dispatcher does not call
    /// [`DetectionEvent::validate`], so an event that fails it reaches this
    /// method with the others.
    async fn insert_detection_events(
        &self,
        _model_id: u32,
        _round: u32,
        _events: &[DetectionEvent],
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn insert_model(&self, _model: &[u8]) -> Result<u32, String> {
        Err("not supported".to_string())
    }

    async fn insert_time_series(
        &self,
        _time_series: &[TimeSeriesUpdate],
        _model_id: u32,
        _batch_ts: i64,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn remove_model(&self, _name: &str) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn renew_certificate(&self, _peer: &str) -> Result<(String, String), String> {
        Err("not supported".to_string())
    }

    async fn update_clusters(
        &self,
        _input: &[UpdateClusterRequest],
        _model_id: u32,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn update_model(&self, _model: &[u8]) -> Result<u32, String> {
        Err("not supported".to_string())
    }

    async fn update_outliers(
        &self,
        _outliers: &[OutlierInfo],
        _model_id: u32,
        _timestamp: i64,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    /// Answers request 45, the DAI extractor configuration for the
    /// `sensors` agent `peer` takes.
    ///
    /// A list that is exactly `["all"]` stands for every sensor that belongs
    /// to a customer. Otherwise the answer covers only the named sensors that
    /// belong to a customer; other names are left out, not reported as
    /// errors. See [`DaiExtractorConfig`] for what the answer holds.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// manager refuses it.
    async fn get_dai_extractor_config(
        &self,
        _peer: &str,
        _sensors: &[String],
    ) -> Result<DaiExtractorConfig, String> {
        Err("not supported".to_string())
    }

    /// Answers request 46, the DAI read cursors for the `sensors` agent
    /// `peer` takes.
    ///
    /// The sensor list is read as for
    /// [`get_dai_extractor_config`](Self::get_dai_extractor_config). See
    /// [`DaiCursors`] for what the answer holds.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// manager refuses it.
    async fn get_dai_cursors(
        &self,
        _peer: &str,
        _sensors: &[String],
    ) -> Result<DaiCursors, String> {
        Err("not supported".to_string())
    }

    /// Accepts request 47, one part of one send of the observations of a
    /// slot from agent `peer`.
    ///
    /// The batch is taken by value, so it can be handed to another task
    /// without a copy. See [`DaiObservationBatch`] for the rules the manager
    /// applies to it and [`DaiStoreAck`] for the answers.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// manager refuses it.
    async fn send_dai_observations(
        &self,
        _peer: &str,
        _batch: DaiObservationBatch,
    ) -> Result<DaiStoreAck, String> {
        Err("not supported".to_string())
    }

    /// Answers request 48, starting a round of range day `unit` for agent
    /// `peer`, which holds `restore_generation`.
    ///
    /// A grant raises the unit's version and grants a lease with a fresh
    /// random lease token. See [`DaiRangeGrant`] for the answers.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// manager refuses it.
    async fn begin_dai_range_day(
        &self,
        _peer: &str,
        _unit: &DaiRangeUnit,
        _restore_generation: u64,
    ) -> Result<DaiRangeGrant, String> {
        Err("not supported".to_string())
    }

    /// Answers request 49, renewing the lease `lease_token` on range day
    /// `unit` for agent `peer`.
    ///
    /// Answers the new lease end, in nanoseconds since the UNIX epoch, or
    /// `None` when the token is no longer the unit's current one, and the
    /// agent stops.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// manager refuses it.
    async fn renew_dai_range_day(
        &self,
        _peer: &str,
        _unit: &DaiRangeUnit,
        _lease_token: u64,
    ) -> Result<Option<i64>, String> {
        Err("not supported".to_string())
    }

    /// Accepts request 50, the counts of a range day from agent `peer`.
    ///
    /// The day is taken by value, so it can be handed to another task
    /// without a copy. The answer is [`DaiStoreAck::Stored`] also for a
    /// result from a superseded lease, which the manager discards; see
    /// [`DaiRangeDay`].
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// manager refuses it.
    async fn send_dai_range_day(
        &self,
        _peer: &str,
        _day: DaiRangeDay,
    ) -> Result<DaiStoreAck, String> {
        Err("not supported".to_string())
    }

    /// Accepts request 51, the late range days and subnets agent `peer`
    /// reports, and answers the marks assigned to `late_days`.
    ///
    /// `late_subnets` are recorded without a mark; see [`DaiRangeLate`].
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// manager refuses it, for example when the restore generation differs.
    /// An error means nothing was recorded, and the agent calls
    /// `get_dai_cursors` again before reporting.
    async fn report_dai_range_late(
        &self,
        _peer: &str,
        _late: &DaiRangeLate,
    ) -> Result<Vec<DaiRangeMark>, String> {
        Err("not supported".to_string())
    }

    /// Accepts the model a run of the Unsupervised Engine `peer` produced.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// Central Manager refuses it.
    async fn upload_run_model(
        &self,
        _peer: &str,
        _run_id: u32,
        _model: &[u8],
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    /// Records the state the Unsupervised Engine `peer` reports for a run.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// Central Manager refuses it.
    async fn report_run(
        &self,
        _peer: &str,
        _run_id: u32,
        _state: ReportedRunState,
        _reason: Option<&str>,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    /// Records the runs the Unsupervised Engine `peer` still has.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// Central Manager refuses it.
    async fn report_active_runs(&self, _peer: &str, _run_ids: &[u32]) -> Result<(), String> {
        Err("not supported".to_string())
    }

    /// Records the status the Unsupervised Engine `peer` reports for a
    /// detector.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// Central Manager refuses it.
    async fn report_detector_status(
        &self,
        _peer: &str,
        _report: &DetectorStatusReport,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    /// Records the raw events the Semi-supervised Engine `peer` skipped
    /// before detection because they matched an exclusion-list entry, counted
    /// per entry and UTC date.
    ///
    /// # Errors
    ///
    /// Returns an error message if the request is not supported or the
    /// Central Manager refuses it.
    async fn report_exclusion_counts(
        &self,
        _peer: &str,
        _report: &EngineExclusionReport,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }
}

/// Handles requests to the server.
///
/// This handles only a subset of the requests that the server can receive. If
/// the request is not supported, the request code is returned to the caller.
///
/// No authorization checks are performed; all requests are
/// dispatched directly.  Use [`handle_authorized`] to gate
/// requests through an [`Authorizer`](crate::auth::Authorizer).
///
/// # Errors
///
/// - There was an error reading from the stream.
/// - There was an error writing to the stream.
/// - An unknown request code was received.
/// - The arguments to the request were invalid.
pub async fn handle<H>(
    handler: &mut H,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peer: &str,
) -> io::Result<Option<(u32, Vec<u8>)>>
where
    H: Handler + Sync,
{
    let peer_ctx = crate::auth::PeerContext::new(peer);
    handle_authorized(handler, send, recv, &peer_ctx, &crate::auth::NoopAuthorizer).await
}

/// Handles requests to the server with authorization using an
/// [`AuthorizerV2`](crate::auth::AuthorizerV2).
///
/// Like [`handle_authorized`], but receives an
/// [`AuthorizationContext`](crate::auth::AuthorizationContext)
/// and an [`AuthorizerV2`](crate::auth::AuthorizerV2) instead
/// of a bare [`PeerContext`](crate::auth::PeerContext) and
/// [`Authorizer`](crate::auth::Authorizer).  This allows
/// authorization policies to use the richer metadata carried by
/// `AuthorizationContext` (agent kind, roles, protocol metadata,
/// and application-supplied attributes).
///
/// Existing callers should continue to use [`handle_authorized`]
/// with the legacy [`Authorizer`](crate::auth::Authorizer) trait.  When migrating to the
/// richer context, wrap legacy authorizers with
/// [`AuthorizerV2Adapter`](crate::auth::AuthorizerV2Adapter) or
/// implement [`AuthorizerV2`](crate::auth::AuthorizerV2)
/// directly.
///
/// # Errors
///
/// - There was an error reading from the stream.
/// - There was an error writing to the stream.
/// - An unknown request code was received.
/// - The arguments to the request were invalid.
/// - Authorization was denied for a request.
#[allow(clippy::too_many_lines)]
pub async fn handle_authorized_with_context<H>(
    handler: &mut H,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    auth_ctx: &crate::auth::AuthorizationContext,
    authorizer: &dyn crate::auth::AuthorizerV2,
) -> io::Result<Option<(u32, Vec<u8>)>>
where
    H: Handler + Sync,
{
    let peer_name = auth_ctx.peer_identity().name();
    let mut buf = Vec::new();
    loop {
        let (code, body) = match oinq::message::recv_request_raw(recv, &mut buf).await {
            Ok(res) => res,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        let req_code = RequestCode::from_primitive(code);

        if let Some(service_id) = crate::service_id::from_server_request_code(req_code)
            && let Err(e) = authorizer.authorize_with_context(auth_ctx, &service_id)
        {
            oinq::request::send_response(
                send,
                &mut buf,
                Err::<(), String>(AUTHORIZATION_DENIED.to_owned()),
            )
            .await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                DispatchError::new(e.kind(), e.to_string()),
            ));
        }

        match req_code {
            RequestCode::GetExclusionList => {
                parse_args::<()>(body)?;
                let result = handler.get_exclusion_list(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetWatchlist => {
                parse_args::<()>(body)?;
                let result = handler.get_watchlist(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetDataSource => {
                let data_source_key = parse_args::<DataSourceKey>(body)?;
                let result = handler.get_data_source(&data_source_key).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetIndicator => {
                let name = parse_args::<String>(body)?;
                let result = handler.get_indicator(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetModel => {
                let name = parse_args::<String>(body)
                    .map_err(|e| DispatchError::from_io(ProtocolErrorKind::InvalidArgs, &e))?;
                let result = handler.get_model(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetModelNames => {
                parse_args::<()>(body)?;
                let result = handler.get_model_names().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetLabelDbPatterns => {
                let db_names = parse_args::<Vec<(&str, &str)>>(body)?;
                let result = handler.get_labeldb_patterns(&db_names).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTorExitNodeList => {
                parse_args::<()>(body)?;
                let result = handler.get_tor_exit_node_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTrustedDomainList => {
                parse_args::<()>(body)?;
                let result = handler.get_trusted_domain_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTrustedUserAgentList => {
                parse_args::<()>(body)?;
                let result = handler.get_trusted_user_agent_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetConfig => {
                parse_args::<()>(body)?;
                let result = handler.get_config(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetInternalNetworkList => {
                parse_args::<()>(body)?;
                let result = handler.get_internal_network_list(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetOutliers => {
                let (model_id, timestamp) = parse_args::<(u32, i64)>(body)
                    .map_err(|e| DispatchError::from_io(ProtocolErrorKind::InvalidArgs, &e))?;
                let result = handler.get_outliers(model_id, timestamp).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetPretrainedModel => {
                let name = parse_args::<String>(body)?;
                let result = handler.get_pretrained_model(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTimeSeriesGenerationPolicyList => {
                parse_args::<()>(body)?;
                let result = handler
                    .get_time_series_generation_policy_list(peer_name)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertColumnStatistics => {
                let (statistics, model_id, batch_ts) =
                    parse_args::<(Vec<ColumnStatisticsUpdate>, u32, i64)>(body)?;
                let result = handler
                    .insert_column_statistics(&statistics, model_id, batch_ts)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertDataSource => {
                let data_source = parse_args::<DataSource>(body)?;
                let result = handler.insert_data_source(&data_source).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertDetectionEvents => {
                let (model_id, round, events) =
                    parse_args::<(u32, u32, Vec<DetectionEvent>)>(body)?;
                let result = handler
                    .insert_detection_events(model_id, round, &events)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertModel => {
                let body = parse_args::<Vec<u8>>(body)?;
                let result = handler.insert_model(&body).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertTimeSeries => {
                let (time_series, model_id, batch_ts) =
                    parse_args::<(Vec<TimeSeriesUpdate>, u32, i64)>(body)?;
                let result = handler
                    .insert_time_series(&time_series, model_id, batch_ts)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::RemoveModel => {
                let name = parse_args::<String>(body)?;
                let result = handler.remove_model(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::RenewCertificate => {
                let result = handler.renew_certificate(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportCustomerDataDeletion => {
                let report = parse_args::<CustomerDataDeletionReport>(body)?;
                let result = handler.report_customer_data_deletion(&report).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateClusters => {
                let (input, model_id) = parse_args::<(Vec<UpdateClusterRequest>, u32)>(body)?;
                let result = handler.update_clusters(&input, model_id).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateModel => {
                let body = parse_args::<Vec<u8>>(body)?;
                let result = handler.update_model(&body).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateOutliers => {
                let (outliers, model_id, timestamp) =
                    parse_args::<(Vec<OutlierInfo>, u32, i64)>(body)?;
                let result = handler
                    .update_outliers(&outliers, model_id, timestamp)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetDaiExtractorConfig => {
                let sensors = parse_args::<Vec<String>>(body)?;
                let result = handler.get_dai_extractor_config(peer_name, &sensors).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetDaiCursors => {
                let sensors = parse_args::<Vec<String>>(body)?;
                let result = handler.get_dai_cursors(peer_name, &sensors).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::SendDaiObservations => {
                let batch = parse_args::<DaiObservationBatch>(body)?;
                let result = handler.send_dai_observations(peer_name, batch).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::BeginDaiRangeDay => {
                let (unit, restore_generation) = parse_args::<(DaiRangeUnit, u64)>(body)?;
                let result = handler
                    .begin_dai_range_day(peer_name, &unit, restore_generation)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::RenewDaiRangeDay => {
                let (unit, lease_token) = parse_args::<(DaiRangeUnit, u64)>(body)?;
                let result = handler
                    .renew_dai_range_day(peer_name, &unit, lease_token)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::SendDaiRangeDay => {
                let day = parse_args::<DaiRangeDay>(body)?;
                let result = handler.send_dai_range_day(peer_name, day).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportDaiRangeLate => {
                let late = parse_args::<DaiRangeLate>(body)?;
                let result = handler.report_dai_range_late(peer_name, &late).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UploadRunModel => {
                let (run_id, model) = parse_args::<(u32, Vec<u8>)>(body)?;
                let result = handler.upload_run_model(peer_name, run_id, &model).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportRun => {
                let (run_id, state, reason) =
                    parse_args::<(u32, ReportedRunState, Option<&str>)>(body)?;
                let result = handler.report_run(peer_name, run_id, state, reason).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportActiveRuns => {
                let run_ids = parse_args::<Vec<u32>>(body)?;
                let result = handler.report_active_runs(peer_name, &run_ids).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportDetectorStatus => {
                let report = parse_args::<DetectorStatusReport>(body)?;
                let result = handler.report_detector_status(peer_name, &report).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportExclusionCounts => {
                let report = parse_args::<EngineExclusionReport>(body)?;
                let result = handler.report_exclusion_counts(peer_name, &report).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::Unknown => {
                oinq::frame::send(
                    send,
                    &mut buf,
                    Err(UNKNOWN_REQUEST_CODE) as Result<(), &str>,
                )
                .await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    DispatchError::new(
                        crate::protocol_error::ProtocolErrorKind::NotSupported,
                        UNKNOWN_REQUEST_CODE,
                    ),
                ));
            }
            _ => {
                return Ok(Some((code, body.into())));
            }
        }
    }
    Ok(None)
}

/// Handles requests to the server with authorization.
///
/// Like [`handle`], but checks each request against the provided
/// [`Authorizer`](crate::auth::Authorizer) before dispatching.
/// The authorizer receives the authenticated
/// [`PeerContext`](crate::auth::PeerContext) and the logical
/// [`ServiceId`](crate::service_id::ServiceId) for every
/// request.  If authorization is denied, an error response is
/// sent to the client and an `io::ErrorKind::PermissionDenied`
/// error is returned.
///
/// # Errors
///
/// - There was an error reading from the stream.
/// - There was an error writing to the stream.
/// - An unknown request code was received.
/// - The arguments to the request were invalid.
/// - Authorization was denied for a request.
#[allow(clippy::too_many_lines)]
pub async fn handle_authorized<H>(
    handler: &mut H,
    send: &mut quinn::SendStream,
    recv: &mut quinn::RecvStream,
    peer: &crate::auth::PeerContext,
    authorizer: &dyn crate::auth::Authorizer,
) -> io::Result<Option<(u32, Vec<u8>)>>
where
    H: Handler + Sync,
{
    let peer_name = peer.name();
    let mut buf = Vec::new();
    loop {
        let (code, body) = match oinq::message::recv_request_raw(recv, &mut buf).await {
            Ok(res) => res,
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => break,
            Err(e) => return Err(e),
        };

        let req_code = RequestCode::from_primitive(code);

        // Authorization check: compute the logical ServiceId and
        // ask the authorizer before dispatching the request.
        if let Some(service_id) = crate::service_id::from_server_request_code(req_code)
            && let Err(e) = authorizer.authorize(peer, &service_id)
        {
            oinq::request::send_response(
                send,
                &mut buf,
                Err::<(), String>(AUTHORIZATION_DENIED.to_owned()),
            )
            .await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                DispatchError::new(e.kind(), e.to_string()),
            ));
        }

        match req_code {
            RequestCode::GetExclusionList => {
                parse_args::<()>(body)?;
                let result = handler.get_exclusion_list(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetWatchlist => {
                parse_args::<()>(body)?;
                let result = handler.get_watchlist(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetDataSource => {
                let data_source_key = parse_args::<DataSourceKey>(body)?;
                let result = handler.get_data_source(&data_source_key).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetIndicator => {
                let name = parse_args::<String>(body)?;
                let result = handler.get_indicator(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetModel => {
                // Classify parse failures as InvalidArgs so callers
                // can distinguish bad input from other I/O errors.
                let name = parse_args::<String>(body)
                    .map_err(|e| DispatchError::from_io(ProtocolErrorKind::InvalidArgs, &e))?;
                let result = handler.get_model(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetModelNames => {
                parse_args::<()>(body)?;
                let result = handler.get_model_names().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetLabelDbPatterns => {
                let db_names = parse_args::<Vec<(&str, &str)>>(body)?;
                let result = handler.get_labeldb_patterns(&db_names).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTorExitNodeList => {
                parse_args::<()>(body)?;
                let result = handler.get_tor_exit_node_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTrustedDomainList => {
                parse_args::<()>(body)?;
                let result = handler.get_trusted_domain_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTrustedUserAgentList => {
                parse_args::<()>(body)?;
                let result = handler.get_trusted_user_agent_list().await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetConfig => {
                parse_args::<()>(body)?;
                let result = handler.get_config(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetInternalNetworkList => {
                parse_args::<()>(body)?;
                let result = handler.get_internal_network_list(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetOutliers => {
                // Classify parse failures as InvalidArgs so callers
                // can distinguish bad input from other I/O errors.
                let (model_id, timestamp) = parse_args::<(u32, i64)>(body)
                    .map_err(|e| DispatchError::from_io(ProtocolErrorKind::InvalidArgs, &e))?;
                let result = handler.get_outliers(model_id, timestamp).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetPretrainedModel => {
                let name = parse_args::<String>(body)?;
                let result = handler.get_pretrained_model(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetTimeSeriesGenerationPolicyList => {
                parse_args::<()>(body)?;
                let result = handler
                    .get_time_series_generation_policy_list(peer_name)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertColumnStatistics => {
                let (statistics, model_id, batch_ts) =
                    parse_args::<(Vec<ColumnStatisticsUpdate>, u32, i64)>(body)?;
                let result = handler
                    .insert_column_statistics(&statistics, model_id, batch_ts)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertDataSource => {
                let data_source = parse_args::<DataSource>(body)?;
                let result = handler.insert_data_source(&data_source).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertDetectionEvents => {
                let (model_id, round, events) =
                    parse_args::<(u32, u32, Vec<DetectionEvent>)>(body)?;
                let result = handler
                    .insert_detection_events(model_id, round, &events)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertModel => {
                let body = parse_args::<Vec<u8>>(body)?;
                let result = handler.insert_model(&body).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::InsertTimeSeries => {
                let (time_series, model_id, batch_ts) =
                    parse_args::<(Vec<TimeSeriesUpdate>, u32, i64)>(body)?;
                let result = handler
                    .insert_time_series(&time_series, model_id, batch_ts)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::RemoveModel => {
                let name = parse_args::<String>(body)?;
                let result = handler.remove_model(&name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::RenewCertificate => {
                let result = handler.renew_certificate(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportCustomerDataDeletion => {
                let report = parse_args::<CustomerDataDeletionReport>(body)?;
                let result = handler.report_customer_data_deletion(&report).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateClusters => {
                let (input, model_id) = parse_args::<(Vec<UpdateClusterRequest>, u32)>(body)?;
                let result = handler.update_clusters(&input, model_id).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateModel => {
                let body = parse_args::<Vec<u8>>(body)?;
                let result = handler.update_model(&body).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateOutliers => {
                let (outliers, model_id, timestamp) =
                    parse_args::<(Vec<OutlierInfo>, u32, i64)>(body)?;
                let result = handler
                    .update_outliers(&outliers, model_id, timestamp)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetDaiExtractorConfig => {
                let sensors = parse_args::<Vec<String>>(body)?;
                let result = handler.get_dai_extractor_config(peer_name, &sensors).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetDaiCursors => {
                let sensors = parse_args::<Vec<String>>(body)?;
                let result = handler.get_dai_cursors(peer_name, &sensors).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::SendDaiObservations => {
                let batch = parse_args::<DaiObservationBatch>(body)?;
                let result = handler.send_dai_observations(peer_name, batch).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::BeginDaiRangeDay => {
                let (unit, restore_generation) = parse_args::<(DaiRangeUnit, u64)>(body)?;
                let result = handler
                    .begin_dai_range_day(peer_name, &unit, restore_generation)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::RenewDaiRangeDay => {
                let (unit, lease_token) = parse_args::<(DaiRangeUnit, u64)>(body)?;
                let result = handler
                    .renew_dai_range_day(peer_name, &unit, lease_token)
                    .await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::SendDaiRangeDay => {
                let day = parse_args::<DaiRangeDay>(body)?;
                let result = handler.send_dai_range_day(peer_name, day).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportDaiRangeLate => {
                let late = parse_args::<DaiRangeLate>(body)?;
                let result = handler.report_dai_range_late(peer_name, &late).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UploadRunModel => {
                let (run_id, model) = parse_args::<(u32, Vec<u8>)>(body)?;
                let result = handler.upload_run_model(peer_name, run_id, &model).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportRun => {
                let (run_id, state, reason) =
                    parse_args::<(u32, ReportedRunState, Option<&str>)>(body)?;
                let result = handler.report_run(peer_name, run_id, state, reason).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportActiveRuns => {
                let run_ids = parse_args::<Vec<u32>>(body)?;
                let result = handler.report_active_runs(peer_name, &run_ids).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportDetectorStatus => {
                let report = parse_args::<DetectorStatusReport>(body)?;
                let result = handler.report_detector_status(peer_name, &report).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::ReportExclusionCounts => {
                let report = parse_args::<EngineExclusionReport>(body)?;
                let result = handler.report_exclusion_counts(peer_name, &report).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::Unknown => {
                oinq::frame::send(
                    send,
                    &mut buf,
                    Err(UNKNOWN_REQUEST_CODE) as Result<(), &str>,
                )
                .await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    DispatchError::new(
                        crate::protocol_error::ProtocolErrorKind::NotSupported,
                        UNKNOWN_REQUEST_CODE,
                    ),
                ));
            }
            _ => {
                return Ok(Some((code, body.into())));
            }
        }
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::test::{TOKEN, channel};
    use crate::types::{
        CustomerDataDeletionOutcome, CustomerDataDeletionReport, CustomerDataDeletionReporter,
    };

    struct ModelHandler {
        insert_model_payload: Arc<Mutex<Option<Vec<u8>>>>,
        update_model_payload: Arc<Mutex<Option<Vec<u8>>>>,
    }

    #[async_trait::async_trait]
    impl Handler for ModelHandler {
        async fn insert_model(&self, model: &[u8]) -> Result<u32, String> {
            *self.insert_model_payload.lock().unwrap() = Some(model.to_vec());
            Ok(42)
        }

        async fn update_model(&self, model: &[u8]) -> Result<u32, String> {
            *self.update_model_payload.lock().unwrap() = Some(model.to_vec());
            Ok(55)
        }
    }

    struct DeletionReportHandler {
        reports: Arc<Mutex<Vec<CustomerDataDeletionReport>>>,
        response: Result<(), String>,
    }

    #[async_trait::async_trait]
    impl Handler for DeletionReportHandler {
        async fn report_customer_data_deletion(
            &self,
            report: &CustomerDataDeletionReport,
        ) -> Result<(), String> {
            self.reports.lock().unwrap().push(report.clone());
            self.response.clone()
        }
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn deletion_report_default_is_not_supported() {
        struct DefaultHandler;
        impl Handler for DefaultHandler {}

        let report = CustomerDataDeletionReport {
            id: 42,
            host_fqdn: "sensor.example.test".to_string(),
            completed_at: Some(1_700_000_100),
            reporter: CustomerDataDeletionReporter::Sensor,
            outcome: CustomerDataDeletionOutcome::Succeeded,
        };
        assert_eq!(
            DefaultHandler.report_customer_data_deletion(&report).await,
            Err("not supported".to_string())
        );
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn authorized_dispatches_deletion_reports_unchanged() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let reports = Arc::new(Mutex::new(Vec::new()));
        let mut handler = DeletionReportHandler {
            reports: Arc::clone(&reports),
            response: Ok(()),
        };
        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);
        let peer = crate::auth::PeerContext::new("test-peer");

        let server_task = tokio::spawn(async move {
            super::handle_authorized(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &peer,
                &crate::auth::NoopAuthorizer,
            )
            .await
        });

        let expected = vec![
            CustomerDataDeletionReport {
                id: 42,
                host_fqdn: "sensor.example.test".to_string(),
                completed_at: Some(1_700_000_123),
                reporter: CustomerDataDeletionReporter::Sensor,
                outcome: CustomerDataDeletionOutcome::Succeeded,
            },
            CustomerDataDeletionReport {
                id: 43,
                host_fqdn: "semi-supervised.example.test".to_string(),
                completed_at: None,
                reporter: CustomerDataDeletionReporter::SemiSupervised,
                outcome: CustomerDataDeletionOutcome::Failed("clock unavailable".to_string()),
            },
        ];

        for report in &expected {
            let response: Result<(), String> = crate::unary_request(
                &mut client_send,
                &mut client_recv,
                u32::from(RequestCode::ReportCustomerDataDeletion),
                report,
            )
            .await
            .unwrap();
            assert_eq!(response, Ok(()));
        }

        drop(client_send);
        drop(client_recv);
        let _ = server_task.await.unwrap();
        assert_eq!(*reports.lock().unwrap(), expected);
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn authorized_with_context_dispatches_report_and_returns_handler_error() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let reports = Arc::new(Mutex::new(Vec::new()));
        let mut handler = DeletionReportHandler {
            reports: Arc::clone(&reports),
            response: Err("database unavailable".to_string()),
        };
        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);
        let peer = crate::auth::PeerContext::new("test-peer");
        let auth_ctx = crate::auth::AuthorizationContext::from_peer_context(&peer);
        let authorizer = crate::auth::AuthorizerV2Adapter::new(crate::auth::NoopAuthorizer);

        let server_task = tokio::spawn(async move {
            super::handle_authorized_with_context(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &auth_ctx,
                &authorizer,
            )
            .await
        });
        let report = CustomerDataDeletionReport {
            id: 44,
            host_fqdn: "semi-supervised.example.test".to_string(),
            completed_at: Some(1_700_001_100),
            reporter: CustomerDataDeletionReporter::SemiSupervised,
            outcome: CustomerDataDeletionOutcome::Failed("permission denied".to_string()),
        };
        let response: Result<(), String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::ReportCustomerDataDeletion),
            &report,
        )
        .await
        .unwrap();

        assert_eq!(response, Err("database unavailable".to_string()));
        drop(client_send);
        drop(client_recv);
        let _ = server_task.await.unwrap();
        assert_eq!(*reports.lock().unwrap(), vec![report]);
    }

    /// A report request from an Unsupervised or a Semi-supervised Engine, as
    /// the server handler received it, with the caller's peer name.
    #[derive(Debug, PartialEq)]
    enum EngineReport {
        UploadRunModel(String, u32, Vec<u8>),
        ReportRun(String, u32, ReportedRunState, Option<String>),
        ReportActiveRuns(String, Vec<u32>),
        ReportDetectorStatus(String, DetectorStatusReport),
        ReportExclusionCounts(String, EngineExclusionReport),
    }

    struct EngineReportHandler {
        received: Arc<Mutex<Vec<EngineReport>>>,
        response: Result<(), String>,
    }

    #[async_trait::async_trait]
    impl Handler for EngineReportHandler {
        async fn upload_run_model(
            &self,
            peer: &str,
            run_id: u32,
            model: &[u8],
        ) -> Result<(), String> {
            self.received
                .lock()
                .unwrap()
                .push(EngineReport::UploadRunModel(
                    peer.to_string(),
                    run_id,
                    model.to_vec(),
                ));
            self.response.clone()
        }

        async fn report_run(
            &self,
            peer: &str,
            run_id: u32,
            state: ReportedRunState,
            reason: Option<&str>,
        ) -> Result<(), String> {
            self.received.lock().unwrap().push(EngineReport::ReportRun(
                peer.to_string(),
                run_id,
                state,
                reason.map(str::to_string),
            ));
            self.response.clone()
        }

        async fn report_active_runs(&self, peer: &str, run_ids: &[u32]) -> Result<(), String> {
            self.received
                .lock()
                .unwrap()
                .push(EngineReport::ReportActiveRuns(
                    peer.to_string(),
                    run_ids.to_vec(),
                ));
            self.response.clone()
        }

        async fn report_detector_status(
            &self,
            peer: &str,
            report: &DetectorStatusReport,
        ) -> Result<(), String> {
            self.received
                .lock()
                .unwrap()
                .push(EngineReport::ReportDetectorStatus(
                    peer.to_string(),
                    report.clone(),
                ));
            self.response.clone()
        }

        async fn report_exclusion_counts(
            &self,
            peer: &str,
            report: &EngineExclusionReport,
        ) -> Result<(), String> {
            self.received
                .lock()
                .unwrap()
                .push(EngineReport::ReportExclusionCounts(
                    peer.to_string(),
                    report.clone(),
                ));
            self.response.clone()
        }
    }

    /// Sends each engine report request once over `client_send`, the
    /// Unsupervised Engine's requests 41 through 44 and the Semi-supervised
    /// Engine's request 52, asserting every answer equals `expected`, and
    /// returns what the handler should have received from `peer`.
    async fn send_engine_reports(
        client_send: &mut quinn::SendStream,
        client_recv: &mut quinn::RecvStream,
        peer: &str,
        expected: &Result<(), String>,
    ) -> Vec<EngineReport> {
        let model = vec![0x00, 0x7f, 0xff];
        let response: Result<(), String> = crate::unary_request(
            client_send,
            client_recv,
            u32::from(RequestCode::UploadRunModel),
            (7_u32, model.as_slice()),
        )
        .await
        .unwrap();
        assert_eq!(&response, expected);

        let response: Result<(), String> = crate::unary_request(
            client_send,
            client_recv,
            u32::from(RequestCode::ReportRun),
            (7_u32, ReportedRunState::Failed, Some("training failed")),
        )
        .await
        .unwrap();
        assert_eq!(&response, expected);

        let run_ids = vec![7, 8, u32::MAX];
        let response: Result<(), String> = crate::unary_request(
            client_send,
            client_recv,
            u32::from(RequestCode::ReportActiveRuns),
            run_ids.as_slice(),
        )
        .await
        .unwrap();
        assert_eq!(&response, expected);

        let reports = crate::test::detector_status_reports();
        for report in &reports {
            let response: Result<(), String> = crate::unary_request(
                client_send,
                client_recv,
                u32::from(RequestCode::ReportDetectorStatus),
                report,
            )
            .await
            .unwrap();
            assert_eq!(&response, expected);
        }

        let exclusion_reports = crate::test::engine_exclusion_reports();
        for report in &exclusion_reports {
            let response: Result<(), String> = crate::unary_request(
                client_send,
                client_recv,
                u32::from(RequestCode::ReportExclusionCounts),
                report,
            )
            .await
            .unwrap();
            assert_eq!(&response, expected);
        }

        let mut sent = vec![
            EngineReport::UploadRunModel(peer.to_string(), 7, model),
            EngineReport::ReportRun(
                peer.to_string(),
                7,
                ReportedRunState::Failed,
                Some("training failed".to_string()),
            ),
            EngineReport::ReportActiveRuns(peer.to_string(), run_ids),
        ];
        sent.extend(
            reports
                .into_iter()
                .map(|report| EngineReport::ReportDetectorStatus(peer.to_string(), report)),
        );
        sent.extend(
            exclusion_reports
                .into_iter()
                .map(|report| EngineReport::ReportExclusionCounts(peer.to_string(), report)),
        );
        sent
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn engine_reports_default_is_not_supported() {
        struct DefaultHandler;
        impl Handler for DefaultHandler {}

        let report = crate::test::detector_status_reports().remove(0);
        let not_supported = Err("not supported".to_string());
        assert_eq!(
            DefaultHandler.upload_run_model("peer", 7, &[1]).await,
            not_supported
        );
        assert_eq!(
            DefaultHandler
                .report_run("peer", 7, ReportedRunState::Started, None)
                .await,
            not_supported
        );
        assert_eq!(
            DefaultHandler.report_active_runs("peer", &[7]).await,
            not_supported
        );
        assert_eq!(
            DefaultHandler.report_detector_status("peer", &report).await,
            not_supported
        );
        let exclusion_report = crate::test::engine_exclusion_reports().remove(0);
        assert_eq!(
            DefaultHandler
                .report_exclusion_counts("peer", &exclusion_report)
                .await,
            not_supported
        );

        // The default answer also reaches the engine over the wire.
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);
        let server_task = tokio::spawn(async move {
            super::handle(
                &mut DefaultHandler,
                &mut server_send,
                &mut server_recv,
                "test-peer",
            )
            .await
        });
        send_engine_reports(
            &mut client_send,
            &mut client_recv,
            "test-peer",
            &not_supported,
        )
        .await;
        drop(client_send);
        drop(client_recv);
        assert!(server_task.await.unwrap().unwrap().is_none());
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn authorized_dispatches_engine_reports_with_peer() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let received = Arc::new(Mutex::new(Vec::new()));
        let mut handler = EngineReportHandler {
            received: Arc::clone(&received),
            response: Ok(()),
        };
        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);
        let peer = crate::auth::PeerContext::new("engine.example.test");

        let server_task = tokio::spawn(async move {
            super::handle_authorized(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &peer,
                &crate::auth::NoopAuthorizer,
            )
            .await
        });
        let expected = send_engine_reports(
            &mut client_send,
            &mut client_recv,
            "engine.example.test",
            &Ok(()),
        )
        .await;

        drop(client_send);
        drop(client_recv);
        assert!(server_task.await.unwrap().unwrap().is_none());
        assert_eq!(*received.lock().unwrap(), expected);
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn authorized_with_context_dispatches_engine_reports_and_returns_handler_error() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let received = Arc::new(Mutex::new(Vec::new()));
        let mut handler = EngineReportHandler {
            received: Arc::clone(&received),
            response: Err("run 7 is not active".to_string()),
        };
        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);
        let peer = crate::auth::PeerContext::new("engine.example.test");
        let auth_ctx = crate::auth::AuthorizationContext::from_peer_context(&peer);
        let authorizer = crate::auth::AuthorizerV2Adapter::new(crate::auth::NoopAuthorizer);

        let server_task = tokio::spawn(async move {
            super::handle_authorized_with_context(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &auth_ctx,
                &authorizer,
            )
            .await
        });
        let expected = send_engine_reports(
            &mut client_send,
            &mut client_recv,
            "engine.example.test",
            &Err("run 7 is not active".to_string()),
        )
        .await;

        drop(client_send);
        drop(client_recv);
        assert!(server_task.await.unwrap().unwrap().is_none());
        assert_eq!(*received.lock().unwrap(), expected);
    }

    /// An authorizer that allows everything and records the service IDs it
    /// was asked about.
    #[derive(Clone, Default)]
    struct RecordingAuthorizer(Arc<Mutex<Vec<crate::service_id::ServiceId>>>);

    impl crate::auth::Authorizer for RecordingAuthorizer {
        fn authorize(
            &self,
            _peer: &crate::auth::PeerContext,
            service: &crate::service_id::ServiceId,
        ) -> Result<(), crate::auth::AuthorizationError> {
            self.0.lock().unwrap().push(*service);
            Ok(())
        }
    }

    /// The service IDs of the DAI requests, in the order
    /// [`send_dai_requests`] sends them.
    const DAI_SERVICES: [crate::service_id::ServiceId; 7] = [
        crate::service_id::SERVER_DAI_GET_EXTRACTOR_CONFIG,
        crate::service_id::SERVER_DAI_GET_CURSORS,
        crate::service_id::SERVER_DAI_SEND_OBSERVATIONS,
        crate::service_id::SERVER_DAI_BEGIN_RANGE_DAY,
        crate::service_id::SERVER_DAI_RENEW_RANGE_DAY,
        crate::service_id::SERVER_DAI_SEND_RANGE_DAY,
        crate::service_id::SERVER_DAI_REPORT_RANGE_LATE,
    ];

    /// Sends one request of each DAI code over the stream, with the
    /// arguments `crate::test::DaiTestHandler` accepts, and asserts every
    /// answer is that handler's reply, or `not supported` when
    /// `supported` is false.
    async fn send_dai_requests(
        client_send: &mut quinn::SendStream,
        client_recv: &mut quinn::RecvStream,
        supported: bool,
    ) {
        use crate::test::{
            DAI_RENEWED_LEASE_END, dai_cursors, dai_extractor_config, dai_observation_batches,
            dai_range_days, dai_range_grants, dai_range_late, dai_range_marks, dai_range_unit,
            dai_sensors, dai_store_acks,
        };

        fn expect<T>(supported: bool, reply: T) -> Result<T, String> {
            if supported {
                Ok(reply)
            } else {
                Err("not supported".to_string())
            }
        }

        let sensors = dai_sensors();
        let response: Result<DaiExtractorConfig, String> = crate::unary_request(
            client_send,
            client_recv,
            u32::from(RequestCode::GetDaiExtractorConfig),
            &sensors,
        )
        .await
        .unwrap();
        assert_eq!(response, expect(supported, dai_extractor_config()));

        let response: Result<DaiCursors, String> = crate::unary_request(
            client_send,
            client_recv,
            u32::from(RequestCode::GetDaiCursors),
            &sensors,
        )
        .await
        .unwrap();
        assert_eq!(response, expect(supported, dai_cursors()));

        let response: Result<DaiStoreAck, String> = crate::unary_request(
            client_send,
            client_recv,
            u32::from(RequestCode::SendDaiObservations),
            &dai_observation_batches()[0],
        )
        .await
        .unwrap();
        assert_eq!(response, expect(supported, dai_store_acks().remove(1)));

        let response: Result<DaiRangeGrant, String> = crate::unary_request(
            client_send,
            client_recv,
            u32::from(RequestCode::BeginDaiRangeDay),
            (dai_range_unit(), 5_u64),
        )
        .await
        .unwrap();
        assert_eq!(response, expect(supported, dai_range_grants().remove(0)));

        let response: Result<Option<i64>, String> = crate::unary_request(
            client_send,
            client_recv,
            u32::from(RequestCode::RenewDaiRangeDay),
            (dai_range_unit(), 0x0bad_cafe_0bad_cafe_u64),
        )
        .await
        .unwrap();
        assert_eq!(response, expect(supported, Some(DAI_RENEWED_LEASE_END)));

        let response: Result<DaiStoreAck, String> = crate::unary_request(
            client_send,
            client_recv,
            u32::from(RequestCode::SendDaiRangeDay),
            &dai_range_days()[0],
        )
        .await
        .unwrap();
        assert_eq!(response, expect(supported, dai_store_acks().remove(1)));

        let response: Result<Vec<DaiRangeMark>, String> = crate::unary_request(
            client_send,
            client_recv,
            u32::from(RequestCode::ReportDaiRangeLate),
            dai_range_late(),
        )
        .await
        .unwrap();
        assert_eq!(response, expect(supported, dai_range_marks()));
    }

    #[tokio::test]
    async fn dai_requests_default_is_not_supported() {
        struct DefaultHandler;
        impl Handler for DefaultHandler {}

        let not_supported = "not supported".to_string();
        let unit = crate::test::dai_range_unit();
        assert_eq!(
            DefaultHandler
                .get_dai_extractor_config("peer", &["all".to_string()])
                .await,
            Err(not_supported.clone())
        );
        assert_eq!(
            DefaultHandler
                .get_dai_cursors("peer", &["all".to_string()])
                .await,
            Err(not_supported.clone())
        );
        assert_eq!(
            DefaultHandler
                .send_dai_observations("peer", crate::test::dai_observation_batches().remove(0))
                .await,
            Err(not_supported.clone())
        );
        assert_eq!(
            DefaultHandler.begin_dai_range_day("peer", &unit, 5).await,
            Err(not_supported.clone())
        );
        assert_eq!(
            DefaultHandler.renew_dai_range_day("peer", &unit, 1).await,
            Err(not_supported.clone())
        );
        assert_eq!(
            DefaultHandler
                .send_dai_range_day("peer", crate::test::dai_range_days().remove(0))
                .await,
            Err(not_supported.clone())
        );
        assert_eq!(
            DefaultHandler
                .report_dai_range_late("peer", &crate::test::dai_range_late())
                .await,
            Err(not_supported)
        );

        // The default answer also reaches the agent over the wire.
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);
        let server_task = tokio::spawn(async move {
            super::handle(
                &mut DefaultHandler,
                &mut server_send,
                &mut server_recv,
                "test-peer",
            )
            .await
        });
        send_dai_requests(&mut client_send, &mut client_recv, false).await;
        drop(client_send);
        drop(client_recv);
        assert!(server_task.await.unwrap().unwrap().is_none());
    }

    #[tokio::test]
    async fn authorized_dispatches_dai_requests() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);
        let authorizer = RecordingAuthorizer::default();
        let services = Arc::clone(&authorizer.0);

        let server_task = tokio::spawn(async move {
            let mut handler = crate::test::DaiTestHandler {
                peer: "agent.example.test",
            };
            super::handle_authorized(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &crate::auth::PeerContext::new("agent.example.test"),
                &authorizer,
            )
            .await
        });
        send_dai_requests(&mut client_send, &mut client_recv, true).await;

        drop(client_send);
        drop(client_recv);
        assert!(server_task.await.unwrap().unwrap().is_none());
        assert_eq!(*services.lock().unwrap(), DAI_SERVICES);
    }

    #[tokio::test]
    async fn authorized_with_context_dispatches_dai_requests() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;
        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);
        let authorizer = RecordingAuthorizer::default();
        let services = Arc::clone(&authorizer.0);

        let server_task = tokio::spawn(async move {
            let mut handler = crate::test::DaiTestHandler {
                peer: "agent.example.test",
            };
            let peer = crate::auth::PeerContext::new("agent.example.test");
            super::handle_authorized_with_context(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &crate::auth::AuthorizationContext::from_peer_context(&peer),
                &crate::auth::AuthorizerV2Adapter::new(authorizer),
            )
            .await
        });
        send_dai_requests(&mut client_send, &mut client_recv, true).await;

        drop(client_send);
        drop(client_recv);
        assert!(server_task.await.unwrap().unwrap().is_none());
        assert_eq!(*services.lock().unwrap(), DAI_SERVICES);
    }

    /// The retired host report codes are unknown: the dispatcher answers
    /// `unknown request code` and stops.
    #[tokio::test]
    async fn retired_host_report_codes_are_unknown() {
        for code in [37_u32, 38] {
            let _lock = TOKEN.lock().await;
            let channel = channel().await;
            let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
            let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);
            let server_task = tokio::spawn(async move {
                let mut handler = crate::test::DaiTestHandler { peer: "test-peer" };
                super::handle(
                    &mut handler,
                    &mut server_send,
                    &mut server_recv,
                    "test-peer",
                )
                .await
            });
            let response: Result<(), String> =
                crate::unary_request(&mut client_send, &mut client_recv, code, ())
                    .await
                    .unwrap();
            assert_eq!(response, Err(UNKNOWN_REQUEST_CODE.to_string()));
            let error = server_task.await.unwrap().unwrap_err();
            assert_eq!(
                ProtocolErrorKind::of_io_error(&error),
                ProtocolErrorKind::NotSupported
            );
        }
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn insert_and_update_model_deserialize_payload() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let insert_model_payload = Arc::new(Mutex::new(None));
        let update_model_payload = Arc::new(Mutex::new(None));

        let mut handler = ModelHandler {
            insert_model_payload: Arc::clone(&insert_model_payload),
            update_model_payload: Arc::clone(&update_model_payload),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            super::handle(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                "test-peer",
            )
            .await
        });

        let insert_payload = vec![0x10, 0x20, 0x30, 0x40];
        let insert_res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::InsertModel),
            insert_payload.clone(),
        )
        .await
        .unwrap();
        assert_eq!(insert_res.unwrap(), 42);

        let update_payload = vec![0x01, 0x02, 0x03];
        let update_res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::UpdateModel),
            update_payload.clone(),
        )
        .await
        .unwrap();
        assert_eq!(update_res.unwrap(), 55);

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        match server_res {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {}
            Err(e) => panic!("unexpected server error: {e:?}"),
        }
        assert_eq!(*insert_model_payload.lock().unwrap(), Some(insert_payload));
        assert_eq!(*update_model_payload.lock().unwrap(), Some(update_payload));
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn authorization_allowed() {
        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let insert_model_payload = Arc::new(Mutex::new(None));

        let mut handler = ModelHandler {
            insert_model_payload: Arc::clone(&insert_model_payload),
            update_model_payload: Arc::new(Mutex::new(None)),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let peer = crate::auth::PeerContext::new("test-peer");
        let authorizer = crate::auth::NoopAuthorizer;

        let server_task = tokio::spawn(async move {
            super::handle_authorized(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &peer,
                &authorizer,
            )
            .await
        });

        let payload = vec![0x10, 0x20];
        let res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::InsertModel),
            payload,
        )
        .await
        .unwrap();
        assert_eq!(res.unwrap(), 42);

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        match server_res {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {}
            Err(e) => panic!("unexpected server error: {e:?}"),
        }
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn authorization_denied() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};

        struct DenyAll;
        impl Authorizer for DenyAll {
            fn authorize(
                &self,
                _peer: &PeerContext,
                _service: &crate::service_id::ServiceId,
            ) -> Result<(), AuthorizationError> {
                Err(AuthorizationError::new("test denial"))
            }
        }

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let mut handler = ModelHandler {
            insert_model_payload: Arc::new(Mutex::new(None)),
            update_model_payload: Arc::new(Mutex::new(None)),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let peer = PeerContext::new("test-peer");
        let authorizer = DenyAll;

        let server_task = tokio::spawn(async move {
            super::handle_authorized(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &peer,
                &authorizer,
            )
            .await
        });

        // Client sends InsertModel — should be denied
        let res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::InsertModel),
            vec![0x10, 0x20],
        )
        .await
        .unwrap();
        assert_eq!(res, Err("authorization denied".to_string()));

        // Server should return PermissionDenied error
        let server_res = server_task.await.unwrap();
        assert!(server_res.is_err());
        assert_eq!(
            server_res.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn authorization_selective() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};

        /// Allows model operations but denies config access.
        struct AllowModelsOnly;
        impl Authorizer for AllowModelsOnly {
            fn authorize(
                &self,
                _peer: &PeerContext,
                service: &crate::service_id::ServiceId,
            ) -> Result<(), AuthorizationError> {
                if service.family == "server.model" {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("only model APIs allowed"))
                }
            }
        }

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let insert_model_payload = Arc::new(Mutex::new(None));

        let mut handler = ModelHandler {
            insert_model_payload: Arc::clone(&insert_model_payload),
            update_model_payload: Arc::new(Mutex::new(None)),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let peer = PeerContext::new("test-peer");
        let authorizer = AllowModelsOnly;

        let server_task = tokio::spawn(async move {
            super::handle_authorized(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &peer,
                &authorizer,
            )
            .await
        });

        // InsertModel is in server.model family — should be allowed
        let res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::InsertModel),
            vec![0xAA, 0xBB],
        )
        .await
        .unwrap();
        assert_eq!(res.unwrap(), 42);

        // GetConfig is in server.config family — should be denied
        let res: Result<String, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::GetConfig),
            (),
        )
        .await
        .unwrap();
        assert_eq!(res, Err("authorization denied".to_string()));

        // Server should return PermissionDenied for the denied
        // request.
        let server_res = server_task.await.unwrap();
        assert!(server_res.is_err());
        assert_eq!(
            server_res.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );

        // Verify the allowed request was actually processed
        assert!(insert_model_payload.lock().unwrap().is_some());
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn authorization_denied_maps_to_forbidden() {
        use crate::auth::{AuthorizationError, Authorizer, PeerContext};
        use crate::protocol_error::ProtocolErrorKind;

        struct DenyAll;
        impl Authorizer for DenyAll {
            fn authorize(
                &self,
                _peer: &PeerContext,
                _service: &crate::service_id::ServiceId,
            ) -> Result<(), AuthorizationError> {
                Err(AuthorizationError::new("test denial"))
            }
        }

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let mut handler = ModelHandler {
            insert_model_payload: Arc::new(Mutex::new(None)),
            update_model_payload: Arc::new(Mutex::new(None)),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let peer = PeerContext::new("test-peer");
        let authorizer = DenyAll;

        let server_task = tokio::spawn(async move {
            super::handle_authorized(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &peer,
                &authorizer,
            )
            .await
        });

        let _res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::InsertModel),
            vec![0x10, 0x20],
        )
        .await
        .unwrap();

        let server_err = server_task.await.unwrap().unwrap_err();
        assert_eq!(server_err.kind(), io::ErrorKind::PermissionDenied);
        assert_eq!(
            ProtocolErrorKind::of_io_error(&server_err),
            ProtocolErrorKind::Forbidden,
        );
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn unknown_request_code_maps_to_not_supported() {
        use crate::protocol_error::ProtocolErrorKind;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let mut handler = ModelHandler {
            insert_model_payload: Arc::new(Mutex::new(None)),
            update_model_payload: Arc::new(Mutex::new(None)),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            super::handle(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                "test-peer",
            )
            .await
        });

        // Send a request with the Unknown request code
        let _res: Result<(), String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::Unknown),
            (),
        )
        .await
        .unwrap();

        let server_err = server_task.await.unwrap().unwrap_err();
        assert_eq!(server_err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            ProtocolErrorKind::of_io_error(&server_err),
            ProtocolErrorKind::NotSupported,
        );
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn malformed_args_maps_to_invalid_args() {
        use crate::protocol_error::ProtocolErrorKind;

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let mut handler = ModelHandler {
            insert_model_payload: Arc::new(Mutex::new(None)),
            update_model_payload: Arc::new(Mutex::new(None)),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, client_recv) = (channel.client.send, channel.client.recv);

        let server_task = tokio::spawn(async move {
            super::handle(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                "test-peer",
            )
            .await
        });

        // Send a GetModel request with a wrong payload type (unit
        // instead of String). The server's parse_args will fail.
        let mut buf = Vec::new();
        oinq::message::send_request(
            &mut client_send,
            &mut buf,
            u32::from(RequestCode::GetModel),
            (),
        )
        .await
        .unwrap();

        drop(client_send);
        drop(client_recv);

        let server_err = server_task.await.unwrap().unwrap_err();
        assert_eq!(
            ProtocolErrorKind::of_io_error(&server_err),
            ProtocolErrorKind::InvalidArgs,
            "parse failure should classify as InvalidArgs"
        );
    }

    // -- handle_authorized_with_context tests -----------------

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn with_context_allowed_via_adapter() {
        use crate::auth::{AuthorizerV2Adapter, NoopAuthorizer, PeerContext};

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let insert_model_payload = Arc::new(Mutex::new(None));

        let mut handler = ModelHandler {
            insert_model_payload: Arc::clone(&insert_model_payload),
            update_model_payload: Arc::new(Mutex::new(None)),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        let peer = PeerContext::new("test-peer");
        let auth_ctx = crate::auth::AuthorizationContext::from_peer_context(&peer);
        let authorizer = AuthorizerV2Adapter::new(NoopAuthorizer);

        let server_task = tokio::spawn(async move {
            super::handle_authorized_with_context(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &auth_ctx,
                &authorizer,
            )
            .await
        });

        let payload = vec![0x10, 0x20];
        let res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::InsertModel),
            payload,
        )
        .await
        .unwrap();
        assert_eq!(res.unwrap(), 42);

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        match server_res {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {}
            Err(e) => panic!("unexpected server error: {e:?}"),
        }
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn with_context_denied_by_v2_authorizer() {
        use crate::auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext};

        struct DenyNonAdmin;
        impl AuthorizerV2 for DenyNonAdmin {
            fn authorize_with_context(
                &self,
                ctx: &AuthorizationContext,
                _service: &crate::service_id::ServiceId,
            ) -> Result<(), AuthorizationError> {
                if ctx.roles().is_some_and(|r| r.iter().any(|s| s == "admin")) {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("admin required"))
                }
            }
        }

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let mut handler = ModelHandler {
            insert_model_payload: Arc::new(Mutex::new(None)),
            update_model_payload: Arc::new(Mutex::new(None)),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        // No admin role → denied.
        let peer = PeerContext::new("test-peer");
        let auth_ctx = AuthorizationContext::from_peer_context(&peer);
        let authorizer = DenyNonAdmin;

        let server_task = tokio::spawn(async move {
            super::handle_authorized_with_context(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &auth_ctx,
                &authorizer,
            )
            .await
        });

        let res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::InsertModel),
            vec![0x10, 0x20],
        )
        .await
        .unwrap();
        assert_eq!(res, Err("authorization denied".to_string()));

        let server_res = server_task.await.unwrap();
        assert!(server_res.is_err());
        assert_eq!(
            server_res.unwrap_err().kind(),
            io::ErrorKind::PermissionDenied,
        );
    }

    #[tokio::test]
    #[cfg(feature = "server")]
    async fn with_context_allowed_by_role() {
        use crate::auth::{AuthorizationContext, AuthorizationError, AuthorizerV2, PeerContext};

        struct RequireAdmin;
        impl AuthorizerV2 for RequireAdmin {
            fn authorize_with_context(
                &self,
                ctx: &AuthorizationContext,
                _service: &crate::service_id::ServiceId,
            ) -> Result<(), AuthorizationError> {
                if ctx.roles().is_some_and(|r| r.iter().any(|s| s == "admin")) {
                    Ok(())
                } else {
                    Err(AuthorizationError::new("admin required"))
                }
            }
        }

        let _lock = TOKEN.lock().await;
        let channel = channel().await;

        let insert_model_payload = Arc::new(Mutex::new(None));

        let mut handler = ModelHandler {
            insert_model_payload: Arc::clone(&insert_model_payload),
            update_model_payload: Arc::new(Mutex::new(None)),
        };

        let (mut server_send, mut server_recv) = (channel.server.send, channel.server.recv);
        let (mut client_send, mut client_recv) = (channel.client.send, channel.client.recv);

        // With admin role → allowed.
        let peer = PeerContext::new("test-peer");
        let auth_ctx = AuthorizationContext::from_authenticated_inputs(
            &peer,
            None,
            Some(vec!["admin".to_owned()]),
            None,
            None,
        );
        let authorizer = RequireAdmin;

        let server_task = tokio::spawn(async move {
            super::handle_authorized_with_context(
                &mut handler,
                &mut server_send,
                &mut server_recv,
                &auth_ctx,
                &authorizer,
            )
            .await
        });

        let payload = vec![0x10, 0x20];
        let res: Result<u32, String> = crate::unary_request(
            &mut client_send,
            &mut client_recv,
            u32::from(RequestCode::InsertModel),
            payload,
        )
        .await
        .unwrap();
        assert_eq!(res.unwrap(), 42);

        drop(client_send);
        drop(client_recv);

        let server_res = server_task.await.unwrap();
        match server_res {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotConnected => {}
            Err(e) => panic!("unexpected server error: {e:?}"),
        }
    }
}
