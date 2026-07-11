use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::sync::Arc;

use mcp_toolkit_auth::upstream_oauth::{
    BrowserLaunchMode, LoopbackOAuthOptions, OAuthAuthorizationOptions, OAuthClientConfig,
    OAuthRefreshConfig, OAuthTokenSet, PendingOAuthAuthorization, RefreshTokenFileStore,
    RefreshTokenProvider, SecretString, StoredRefreshToken, UpstreamOAuthError,
    oauth_callback_correlation_key, prepare_authorization, start_loopback_authorization,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use url::Url;

use crate::config::CloudflareOAuthConfig;

const PROVIDER: &str = "cloudflare";

#[derive(Debug, Error)]
pub enum CloudflareOAuthError {
    #[error("Cloudflare upstream OAuth is not configured")]
    NotConfigured,
    #[error("Cloudflare upstream OAuth has no stored grant; run cloudflare_auth_login")]
    LoginRequired,
    #[error("too many pending Cloudflare OAuth transactions")]
    PendingLimit,
    #[error("the Cloudflare OAuth callback transaction is unknown, expired, or already consumed")]
    UnknownTransaction,
    #[error("the stored Cloudflare OAuth grant does not match this client configuration")]
    StoredGrantMismatch,
    #[error(transparent)]
    Toolkit(#[from] UpstreamOAuthError),
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudflareOAuthStatus {
    pub enabled: bool,
    pub client_configured: bool,
    pub callback_configured: bool,
    pub scopes: Vec<String>,
    pub token_cache_present: bool,
    pub token_cache_usable: bool,
    pub pending_transactions: usize,
    pub last_login_status: Option<&'static str>,
    pub credential_precedence: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudflareOAuthLogin {
    pub authorization_url: String,
    pub callback_url: String,
    pub scopes: Vec<String>,
    pub expires_in_seconds: u64,
    pub completion_mode: &'static str,
}

struct PendingTransaction {
    principal_key: String,
    authorization: PendingOAuthAuthorization,
    _permit: OwnedSemaphorePermit,
}

impl std::fmt::Debug for PendingTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PendingTransaction")
            .field("principal_key", &self.principal_key)
            .field("authorization", &self.authorization)
            .finish()
    }
}

pub struct CloudflareOAuthManager {
    config: CloudflareOAuthConfig,
    client: Option<OAuthClientConfig>,
    pending: Mutex<HashMap<String, PendingTransaction>>,
    loopback_pending: Mutex<HashSet<String>>,
    login_status: Mutex<HashMap<String, &'static str>>,
    token_providers: Mutex<HashMap<String, Arc<RefreshTokenProvider>>>,
    pending_slots: Arc<Semaphore>,
}

impl std::fmt::Debug for CloudflareOAuthManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareOAuthManager")
            .field("config", &self.config)
            .field("client", &self.client)
            .finish_non_exhaustive()
    }
}

impl CloudflareOAuthManager {
    pub fn new(config: CloudflareOAuthConfig) -> Result<Self, CloudflareOAuthError> {
        let client = if config.enabled {
            Some(
                OAuthClientConfig::new(
                    config.client_id.clone().unwrap_or_default(),
                    config.client_secret.clone().map(SecretString::new),
                    config.authorization_endpoint.clone(),
                    config.token_endpoint.clone(),
                )?
                .with_token_auth_method(config.token_auth_method),
            )
        } else {
            None
        };
        let max_pending_transactions = config.max_pending_transactions;
        Ok(Self {
            config,
            client,
            pending: Mutex::new(HashMap::new()),
            loopback_pending: Mutex::new(HashSet::new()),
            login_status: Mutex::new(HashMap::new()),
            token_providers: Mutex::new(HashMap::new()),
            pending_slots: Arc::new(Semaphore::new(max_pending_transactions)),
        })
    }

    pub fn disabled() -> Self {
        Self::new(CloudflareOAuthConfig::default())
            .expect("disabled OAuth configuration must be valid")
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub async fn status(&self, principal: Option<&str>) -> CloudflareOAuthStatus {
        let cache = principal.map(|principal| {
            self.store_for_principal_key(&principal_key(principal))
                .load()
        });
        let principal_key = principal.map(principal_key);
        let mut pending = self.pending.lock().await;
        pending.retain(|_, item| !item.authorization.is_expired());
        let hosted_pending = principal_key.as_ref().map_or(0, |key| {
            pending
                .values()
                .filter(|item| &item.principal_key == key)
                .count()
        });
        let loopback_pending = match principal_key.as_ref() {
            Some(key) if self.loopback_pending.lock().await.contains(key) => 1,
            _ => 0,
        };
        let last_login_status = match principal_key.as_ref() {
            Some(key) => self.login_status.lock().await.get(key).copied(),
            None => None,
        };
        CloudflareOAuthStatus {
            enabled: self.config.enabled,
            client_configured: self.client.is_some(),
            callback_configured: self.config.callback_url.is_some(),
            scopes: self.config.scopes.clone(),
            token_cache_present: cache
                .as_ref()
                .is_some_and(|result| result.as_ref().is_ok_and(Option::is_some)),
            token_cache_usable: cache.as_ref().is_none_or(Result::is_ok),
            pending_transactions: hosted_pending + loopback_pending,
            last_login_status,
            credential_precedence: "request_header_then_config_token_then_upstream_oauth",
        }
    }

    pub async fn start_login(
        self: &Arc<Self>,
        principal: &str,
        force_consent: bool,
    ) -> Result<CloudflareOAuthLogin, CloudflareOAuthError> {
        let client = self
            .client
            .clone()
            .ok_or(CloudflareOAuthError::NotConfigured)?;
        let callback_url = self
            .config
            .callback_url
            .clone()
            .ok_or(CloudflareOAuthError::NotConfigured)?;
        let principal_key = principal_key(principal);
        let permit = self
            .pending_slots
            .clone()
            .try_acquire_owned()
            .map_err(|_| CloudflareOAuthError::PendingLimit)?;
        if let Some(mut options) = loopback_options(&callback_url, self.config.transaction_timeout)?
        {
            if force_consent {
                options
                    .extra_authorization_params
                    .push(("prompt".to_string(), "consent".to_string()));
            }
            let authorization =
                start_loopback_authorization(client.clone(), self.config.scopes.clone(), options)
                    .await?;
            let result = CloudflareOAuthLogin {
                authorization_url: authorization.authorization_url().to_string(),
                callback_url: authorization.redirect_uri().to_string(),
                scopes: authorization.scopes().to_vec(),
                expires_in_seconds: self.config.transaction_timeout.as_secs(),
                completion_mode: "loopback_callback",
            };
            self.loopback_pending
                .lock()
                .await
                .insert(principal_key.clone());
            self.login_status
                .lock()
                .await
                .insert(principal_key.clone(), "pending");
            let manager = Arc::clone(self);
            tokio::spawn(async move {
                let _permit = permit;
                let outcome = match authorization.finish().await {
                    Ok(token_set) => manager.persist_token_set(&principal_key, token_set).await,
                    Err(err) => Err(CloudflareOAuthError::Toolkit(err)),
                };
                manager.login_status.lock().await.insert(
                    principal_key.clone(),
                    if outcome.is_ok() {
                        "succeeded"
                    } else {
                        "failed"
                    },
                );
                manager.loopback_pending.lock().await.remove(&principal_key);
            });
            return Ok(result);
        }
        let mut options = OAuthAuthorizationOptions::new(callback_url.clone())
            .with_timeout(self.config.transaction_timeout);
        if force_consent {
            options = options.with_extra_authorization_param("prompt", "consent");
        }
        let authorization = prepare_authorization(client, self.config.scopes.clone(), options)?;
        let result = CloudflareOAuthLogin {
            authorization_url: authorization.authorization_url().to_string(),
            callback_url,
            scopes: authorization.scopes().to_vec(),
            expires_in_seconds: self.config.transaction_timeout.as_secs(),
            completion_mode: "hosted_callback",
        };
        let correlation_key = authorization.correlation_key();
        let mut pending = self.pending.lock().await;
        pending.retain(|_, item| {
            !item.authorization.is_expired() && item.principal_key != principal_key
        });
        pending.insert(
            correlation_key,
            PendingTransaction {
                principal_key,
                authorization,
                _permit: permit,
            },
        );
        self.login_status
            .lock()
            .await
            .insert(principal_key, "pending");
        Ok(result)
    }

    pub async fn finish_callback(
        &self,
        code: Option<&str>,
        state: Option<&str>,
        error: Option<&str>,
    ) -> Result<(), CloudflareOAuthError> {
        if !self.config.enabled {
            return Err(CloudflareOAuthError::NotConfigured);
        }
        let state = state.ok_or(CloudflareOAuthError::UnknownTransaction)?;
        let transaction = self
            .pending
            .lock()
            .await
            .remove(&oauth_callback_correlation_key(state))
            .ok_or(CloudflareOAuthError::UnknownTransaction)?;
        let token_set = transaction
            .authorization
            .finish(code, Some(state), error)
            .await?;
        let principal_key = transaction.principal_key;
        let result = self.persist_token_set(&principal_key, token_set).await;
        self.login_status.lock().await.insert(
            principal_key,
            if result.is_ok() {
                "succeeded"
            } else {
                "failed"
            },
        );
        result
    }

    pub async fn clear(&self, principal: &str) -> Result<bool, CloudflareOAuthError> {
        let principal_key = principal_key(principal);
        let store = self.store_for_principal_key(&principal_key);
        let existed = store.load()?.is_some();
        store.clear()?;
        self.token_providers.lock().await.remove(&principal_key);
        Ok(existed)
    }

    pub async fn access_token(
        &self,
        principal: &str,
    ) -> Result<Option<String>, CloudflareOAuthError> {
        if !self.config.enabled {
            return Ok(None);
        }
        let principal_key = principal_key(principal);
        let store = self.store_for_principal_key(&principal_key);
        let provider = {
            let mut providers = self.token_providers.lock().await;
            if let Some(provider) = providers.get(&principal_key) {
                provider.clone()
            } else {
                let stored = store.load()?.ok_or(CloudflareOAuthError::LoginRequired)?;
                let client = self
                    .client
                    .clone()
                    .ok_or(CloudflareOAuthError::NotConfigured)?;
                if stored.provider != PROVIDER
                    || stored.client_id != client.client_id()
                    || stored.scopes.is_empty()
                {
                    return Err(CloudflareOAuthError::StoredGrantMismatch);
                }
                let refresh =
                    OAuthRefreshConfig::new(client, stored.refresh_token.clone(), stored.scopes)?;
                let provider = Arc::new(RefreshTokenProvider::new(refresh)?);
                providers.insert(principal_key.clone(), provider.clone());
                provider
            }
        };
        let access_token = provider.access_token().await?;
        if let Some(replacement) = provider.take_replacement_refresh_token().await {
            let client_id = self
                .client
                .as_ref()
                .ok_or(CloudflareOAuthError::NotConfigured)?
                .client_id()
                .to_string();
            store.save(&replacement.into_stored_token(PROVIDER, client_id))?;
        }
        Ok(Some(access_token.expose_secret().to_string()))
    }

    fn store_for_principal_key(&self, principal_key: &str) -> RefreshTokenFileStore {
        let base = &self.config.token_cache_path;
        let file_name = base
            .file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("upstream-oauth.json");
        let isolated_name = format!("{file_name}.{principal_key}");
        let path = base
            .parent()
            .map(|parent| parent.join(&isolated_name))
            .unwrap_or_else(|| PathBuf::from(isolated_name));
        RefreshTokenFileStore::new(path)
    }

    async fn persist_token_set(
        &self,
        principal_key: &str,
        token_set: OAuthTokenSet,
    ) -> Result<(), CloudflareOAuthError> {
        let client = self
            .client
            .as_ref()
            .ok_or(CloudflareOAuthError::NotConfigured)?;
        let stored = StoredRefreshToken::from_token_set(
            PROVIDER,
            client,
            self.config.scopes.clone(),
            token_set,
        )?;
        self.store_for_principal_key(principal_key).save(&stored)?;
        self.token_providers.lock().await.remove(principal_key);
        Ok(())
    }
}

fn principal_key(principal: &str) -> String {
    let digest = Sha256::digest(principal.trim().as_bytes());
    format!("{digest:x}")
}

fn loopback_options(
    callback_url: &str,
    timeout: std::time::Duration,
) -> Result<Option<LoopbackOAuthOptions>, CloudflareOAuthError> {
    let url = Url::parse(callback_url).map_err(|_| {
        CloudflareOAuthError::Toolkit(UpstreamOAuthError::InvalidUrl {
            field: "redirect_uri",
            value: "<invalid>".to_string(),
        })
    })?;
    if url.scheme() != "http" {
        return Ok(None);
    }
    if url.host_str() != Some("127.0.0.1") {
        return Ok(None);
    }
    let Some(port) = url.port() else {
        return Ok(None);
    };
    Ok(Some(LoopbackOAuthOptions {
        bind_addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: Some(port),
        callback_path: url.path().to_string(),
        timeout,
        browser: BrowserLaunchMode::Disabled,
        extra_authorization_params: Vec::new(),
        success_html: "Authorization complete. You can close this tab and return to Codex."
            .to_string(),
        error_html:
            "Authorization could not be completed. Return to Codex and start a fresh login."
                .to_string(),
    }))
}

#[cfg(test)]
mod tests {
    use super::{CloudflareOAuthError, CloudflareOAuthManager, loopback_options, principal_key};

    #[test]
    fn principal_keys_are_stable_and_do_not_expose_principal() {
        let key = principal_key("operator@example.test");
        assert_eq!(key.len(), 64);
        assert_eq!(key, principal_key("operator@example.test"));
        assert!(!key.contains("operator"));
    }

    #[tokio::test]
    async fn disabled_manager_reports_no_grant_and_refuses_login() {
        let manager = CloudflareOAuthManager::disabled();
        let status = manager.status(Some("operator")).await;
        assert!(!status.enabled);
        assert!(!status.token_cache_present);
        assert!(matches!(
            manager.start_login("operator", false).await,
            Err(CloudflareOAuthError::NotConfigured)
        ));
    }

    #[test]
    fn fixed_ipv4_loopback_callback_becomes_embedded_listener() {
        let options = loopback_options(
            "http://127.0.0.1:9502/oauth/cloudflare/callback",
            std::time::Duration::from_secs(60),
        )
        .expect("parse callback")
        .expect("loopback options");
        assert_eq!(options.bind_addr, "127.0.0.1".parse().expect("ip"));
        assert_eq!(options.port, Some(9502));
        assert_eq!(options.callback_path, "/oauth/cloudflare/callback");
    }
}
