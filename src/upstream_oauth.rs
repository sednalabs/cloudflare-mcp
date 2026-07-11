use std::collections::HashMap;
use std::sync::Arc;

use mcp_toolkit_auth::upstream_oauth::{
    OAuthAuthorizationOptions, OAuthClientConfig, OAuthRefreshConfig, PendingOAuthAuthorization,
    RefreshTokenFileStore, RefreshTokenProvider, RefreshTokenStore, SecretString,
    StoredRefreshToken, UpstreamOAuthError, oauth_callback_correlation_key, prepare_authorization,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::Mutex;

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
    pub credential_precedence: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct CloudflareOAuthLogin {
    pub authorization_url: String,
    pub callback_url: String,
    pub scopes: Vec<String>,
    pub expires_in_seconds: u64,
}

struct PendingTransaction {
    principal_key: String,
    authorization: PendingOAuthAuthorization,
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
    store: RefreshTokenFileStore,
    pending: Mutex<HashMap<String, PendingTransaction>>,
    token_provider: Mutex<Option<Arc<RefreshTokenProvider>>>,
}

impl std::fmt::Debug for CloudflareOAuthManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CloudflareOAuthManager")
            .field("config", &self.config)
            .field("client", &self.client)
            .field("store", &self.store)
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
        Ok(Self {
            store: RefreshTokenFileStore::new(config.token_cache_path.clone()),
            config,
            client,
            pending: Mutex::new(HashMap::new()),
            token_provider: Mutex::new(None),
        })
    }

    pub fn disabled() -> Self {
        Self::new(CloudflareOAuthConfig::default())
            .expect("disabled OAuth configuration must be valid")
    }

    pub fn enabled(&self) -> bool {
        self.config.enabled
    }

    pub async fn status(&self) -> CloudflareOAuthStatus {
        let cache = self.store.load();
        let mut pending = self.pending.lock().await;
        pending.retain(|_, item| !item.authorization.is_expired());
        CloudflareOAuthStatus {
            enabled: self.config.enabled,
            client_configured: self.client.is_some(),
            callback_configured: self.config.callback_url.is_some(),
            scopes: self.config.scopes.clone(),
            token_cache_present: cache.as_ref().is_ok_and(Option::is_some),
            token_cache_usable: cache.is_ok(),
            pending_transactions: pending.len(),
            credential_precedence: "request_header_then_config_token_then_upstream_oauth",
        }
    }

    pub async fn start_login(
        &self,
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
        };
        let correlation_key = authorization.correlation_key();
        let principal_key = principal_key(principal);
        let mut pending = self.pending.lock().await;
        pending.retain(|_, item| {
            !item.authorization.is_expired() && item.principal_key != principal_key
        });
        if pending.len() >= self.config.max_pending_transactions {
            return Err(CloudflareOAuthError::PendingLimit);
        }
        pending.insert(
            correlation_key,
            PendingTransaction {
                principal_key,
                authorization,
            },
        );
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
        self.store.save(&stored)?;
        *self.token_provider.lock().await = None;
        Ok(())
    }

    pub async fn clear(&self) -> Result<bool, CloudflareOAuthError> {
        let existed = self.store.load()?.is_some();
        self.store.clear()?;
        *self.token_provider.lock().await = None;
        Ok(existed)
    }

    pub async fn access_token(&self) -> Result<Option<String>, CloudflareOAuthError> {
        if !self.config.enabled {
            return Ok(None);
        }
        let provider = {
            let mut slot = self.token_provider.lock().await;
            if let Some(provider) = slot.as_ref() {
                provider.clone()
            } else {
                let stored = self
                    .store
                    .load()?
                    .ok_or(CloudflareOAuthError::LoginRequired)?;
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
                *slot = Some(provider.clone());
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
            self.store
                .save(&replacement.into_stored_token(PROVIDER, client_id))?;
        }
        Ok(Some(access_token.expose_secret().to_string()))
    }
}

fn principal_key(principal: &str) -> String {
    let digest = Sha256::digest(principal.trim().as_bytes());
    format!("{digest:x}")
}

#[cfg(test)]
mod tests {
    use super::principal_key;

    #[test]
    fn principal_keys_are_stable_and_do_not_expose_principal() {
        let key = principal_key("operator@example.test");
        assert_eq!(key.len(), 64);
        assert_eq!(key, principal_key("operator@example.test"));
        assert!(!key.contains("operator"));
    }
}
