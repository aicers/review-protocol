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

use std::{
    collections::{HashMap, HashSet},
    io,
    net::IpAddr,
};

use num_enum::FromPrimitive;
use oinq::request::parse_args;

use super::RequestCode;
use crate::protocol_error::{DispatchError, ProtocolErrorKind};
use crate::types::{
    ColumnStatisticsUpdate, CustomerDataDeletionReport, DataSource, DataSourceKey, EventMessage,
    HostNetworkGroup, LabelDb, OutlierInfo, SamplingPolicy, TimeSeriesUpdate, UpdateClusterRequest,
    UserAgent,
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

    async fn get_allowlist(&self, _peer: &str) -> Result<HostNetworkGroup, String> {
        Err("not supported".to_string())
    }

    async fn get_blocklist(&self, _peer: &str) -> Result<HostNetworkGroup, String> {
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

    async fn get_sampling_policy_list(&self, _peer: &str) -> Result<Vec<SamplingPolicy>, String> {
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

    async fn insert_event_labels(
        &self,
        _model_id: u32,
        _round: u32,
        _event_labels: &[EventMessage],
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

    async fn update_host_ports(
        &self,
        _peer: &str,
        _hosts: &HashMap<IpAddr, HashMap<(u16, u8), u32>>,
    ) -> Result<(), String> {
        Err("not supported".to_string())
    }

    async fn update_host_user_agents(
        &self,
        _peer: &str,
        _hosts: &[(IpAddr, Vec<UserAgent>, Vec<String>)],
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
                Err::<(), String>("authorization denied".to_string()),
            )
            .await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                DispatchError::new(e.kind(), e.to_string()),
            ));
        }

        match req_code {
            RequestCode::GetAllowlist => {
                parse_args::<()>(body)?;
                let result = handler.get_allowlist(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetBlocklist => {
                parse_args::<()>(body)?;
                let result = handler.get_blocklist(peer_name).await;
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
            RequestCode::GetSamplingPolicyList => {
                parse_args::<()>(body)?;
                let result = handler.get_sampling_policy_list(peer_name).await;
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
            RequestCode::InsertEventLabels => {
                let (model_id, round, event_labels) =
                    parse_args::<(u32, u32, Vec<EventMessage>)>(body)?;
                let result = handler
                    .insert_event_labels(model_id, round, &event_labels)
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
            RequestCode::UpdateHostOpenedPorts => {
                let hosts = parse_args::<HashMap<IpAddr, HashMap<(u16, u8), u32>>>(body)?;
                let result = handler.update_host_ports(peer_name, &hosts).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateHostOsAgents => {
                let hosts = parse_args::<Vec<(IpAddr, Vec<UserAgent>, Vec<String>)>>(body)?;
                let result = handler.update_host_user_agents(peer_name, &hosts).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::Unknown => {
                oinq::frame::send(
                    send,
                    &mut buf,
                    Err("unknown request code") as Result<(), &str>,
                )
                .await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    DispatchError::new(
                        crate::protocol_error::ProtocolErrorKind::NotSupported,
                        "unknown request code",
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
                Err::<(), String>("authorization denied".to_string()),
            )
            .await?;
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                DispatchError::new(e.kind(), e.to_string()),
            ));
        }

        match req_code {
            RequestCode::GetAllowlist => {
                parse_args::<()>(body)?;
                let result = handler.get_allowlist(peer_name).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::GetBlocklist => {
                parse_args::<()>(body)?;
                let result = handler.get_blocklist(peer_name).await;
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
            RequestCode::GetSamplingPolicyList => {
                parse_args::<()>(body)?;
                let result = handler.get_sampling_policy_list(peer_name).await;
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
            RequestCode::InsertEventLabels => {
                let (model_id, round, event_labels) =
                    parse_args::<(u32, u32, Vec<EventMessage>)>(body)?;
                let result = handler
                    .insert_event_labels(model_id, round, &event_labels)
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
            RequestCode::UpdateHostOpenedPorts => {
                let hosts = parse_args::<HashMap<IpAddr, HashMap<(u16, u8), u32>>>(body)?;
                let result = handler.update_host_ports(peer_name, &hosts).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::UpdateHostOsAgents => {
                let hosts = parse_args::<Vec<(IpAddr, Vec<UserAgent>, Vec<String>)>>(body)?;
                let result = handler.update_host_user_agents(peer_name, &hosts).await;
                oinq::request::send_response(send, &mut buf, result).await?;
            }
            RequestCode::Unknown => {
                oinq::frame::send(
                    send,
                    &mut buf,
                    Err("unknown request code") as Result<(), &str>,
                )
                .await?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    DispatchError::new(
                        crate::protocol_error::ProtocolErrorKind::NotSupported,
                        "unknown request code",
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
