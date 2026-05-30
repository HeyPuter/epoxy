use anyhow::Context;
use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};

use hyper::Method;
use reqwest::Url;
use serde::{Deserialize, Serialize};
use wisp_mux::{
	extensions::{AnyProtocolExtension, ProtocolExtension, ProtocolExtensionBuilder},
	packet::CloseReason,
	ws::{TransportRead, TransportWrite},
	Role, WispError,
};

use crate::REQWEST_CLIENT;

/// ID of Puter password protocol extension.
pub const PUTER_PASSWORD_PROTOCOL_EXTENSION_ID: u8 = 0x02;

/// Puter auth password protocol extension.
///
/// **Passwords are sent in plain text!!**
///
/// See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#0x02---password-authentication)
#[derive(Debug, Clone)]
pub enum PuterPasswordProtocolExtension {
	/// Password protocol extension before the client INFO packet has been received.
	ServerBeforeClientInfo {
		/// Whether this authentication method is required.
		required: bool,
	},
	/// Password protocol extension after the client INFO packet has been received.
	ServerAfterClientInfo {
		/// Auth endpoint.
		endpoint: Url,
		/// The client's chosen user.
		chosen_user: String,
		/// The client's chosen password.
		chosen_password: String,
	},

	/// Password protocol extension before the server INFO has been received.
	ClientBeforeServerInfo,
	/// Password protocol extension after the server INFO has been received.
	ClientAfterServerInfo {
		/// The user to send to the server.
		user: String,
		/// The password to send to the user.
		password: String,
	},
}

impl PuterPasswordProtocolExtension {
	/// ID of password protocol extension.
	pub const ID: u8 = PUTER_PASSWORD_PROTOCOL_EXTENSION_ID;
}

#[derive(Serialize)]
struct AuthRequest {
	token: String,
}
#[derive(Deserialize)]
struct AuthResponse {
	allow: bool,
}

#[async_trait]
impl ProtocolExtension for PuterPasswordProtocolExtension {
	fn get_id(&self) -> u8 {
		PUTER_PASSWORD_PROTOCOL_EXTENSION_ID
	}

	async fn handle_handshake(
		&mut self,
		_read: &mut dyn TransportRead,
		_write: &mut dyn TransportWrite,
	) -> Result<Option<(CloseReason, WispError)>, WispError> {
		match self {
			Self::ServerAfterClientInfo {
				endpoint,
				chosen_password,
				..
			} => {
				let origin = endpoint.origin().ascii_serialization();

				let res = REQWEST_CLIENT
					.request(Method::POST, endpoint.clone())
					.header("Content-Type", "application/json")
					.header("Origin", origin)
					.json(&AuthRequest {
						token: chosen_password.clone(),
					})
					.send()
					.await
					.context("failed to ask auth server for auth")
					.map_err(|x| WispError::ExtensionImplError(x.into()))?
					.json::<AuthResponse>()
					.await
					.context("auth server gave invalid response")
					.map_err(|x| WispError::ExtensionImplError(x.into()))?;

				if res.allow {
                    Ok(None)
				} else {
					Ok(Some((
						CloseReason::ExtensionsPasswordAuthFailed,
						WispError::PasswordExtensionCredsInvalid,
					)))
				}
			}
			_ => Ok(None),
		}
	}

	fn encode(&self) -> Bytes {
		match self {
			Self::ServerBeforeClientInfo { required } => {
				let mut out = BytesMut::with_capacity(1);
				out.put_u8(u8::from(*required));
				out.freeze()
			}
			Self::ClientAfterServerInfo { user, password } => {
				let mut out = BytesMut::with_capacity(1 + 2 + user.len() + password.len());
				out.put_u8(user.len().try_into().unwrap());
				out.extend_from_slice(user.as_bytes());
				out.put_u16(password.len().try_into().unwrap());
				out.extend_from_slice(password.as_bytes());
				out.freeze()
			}

			Self::ServerAfterClientInfo { .. } | Self::ClientBeforeServerInfo => Bytes::new(),
		}
	}

	fn box_clone(&self) -> Box<dyn ProtocolExtension + Sync + Send> {
		Box::new(self.clone())
	}
}

/// Puter password protocol extension builder.
///
/// **Passwords are sent in plain text!!**
///
/// See [the docs](https://github.com/MercuryWorkshop/wisp-protocol/blob/v2/protocol.md#0x02---password-authentication)
pub enum PuterPasswordProtocolExtensionBuilder {
	/// Password protocol extension builder before the client INFO has been received.
	ServerBeforeClientInfo {
		/// Auth endpoint.
		endpoint: Url,
		/// Whether this authentication method is required.
		required: bool,
	},
	/// Password protocol extension builder after the client INFO has been received.
	ServerAfterClientInfo {
		/// Auth endpoint.
		endpoint: Url,
		/// Whether this authentication method is required.
		required: bool,
	},

	/// Password protocol extension builder before the server INFO has been received.
	ClientBeforeServerInfo {
		/// The credentials to send to the server.
		creds: Option<(String, String)>,
	},
	/// Password protocol extension builder after the server INFO has been received.
	ClientAfterServerInfo {
		/// The credentials to send to the server.
		creds: Option<(String, String)>,
		/// Whether this authentication method is required.
		required: bool,
	},
}

impl PuterPasswordProtocolExtensionBuilder {
	/// ID of password protocol extension.
	pub const ID: u8 = PUTER_PASSWORD_PROTOCOL_EXTENSION_ID;

	/// Create a new server variant of the password protocol extension.
	pub fn new_server(endpoint: Url, required: bool) -> Self {
		Self::ServerBeforeClientInfo { endpoint, required }
	}

	/// Create a new client variant of the password protocol extension with a username and password.
	pub fn new_client(creds: Option<(String, String)>) -> Self {
		Self::ClientBeforeServerInfo { creds }
	}

	/// Get whether this authentication method is required. Could return None if the server has not
	/// sent the password protocol extension.
	pub fn is_required(&self) -> Option<bool> {
		match self {
			Self::ServerBeforeClientInfo { required, .. }
			| Self::ServerAfterClientInfo { required, .. }
			| Self::ClientAfterServerInfo { required, .. } => Some(*required),
			Self::ClientBeforeServerInfo { .. } => None,
		}
	}

	/// Set the credentials sent to the server, if this is a client variant.
	pub fn set_creds(&mut self, credentials: (String, String)) {
		match self {
			Self::ClientBeforeServerInfo { creds } | Self::ClientAfterServerInfo { creds, .. } => {
				*creds = Some(credentials);
			}
			Self::ServerBeforeClientInfo { .. } | Self::ServerAfterClientInfo { .. } => {}
		}
	}
}

impl ProtocolExtensionBuilder for PuterPasswordProtocolExtensionBuilder {
	fn get_id(&self) -> u8 {
		PUTER_PASSWORD_PROTOCOL_EXTENSION_ID
	}

	fn build_to_extension(&mut self, _role: Role) -> Result<AnyProtocolExtension, WispError> {
		match self {
			Self::ServerBeforeClientInfo { required, .. } => {
				Ok(PuterPasswordProtocolExtension::ServerBeforeClientInfo {
					required: *required,
				}
				.into())
			}
			Self::ServerAfterClientInfo { .. } | Self::ClientBeforeServerInfo { .. } => {
				Err(WispError::ExtensionImplNotSupported)
			}
			Self::ClientAfterServerInfo { creds, .. } => {
				let (user, password) = creds.clone().ok_or(WispError::PasswordExtensionNoCreds)?;
				Ok(PuterPasswordProtocolExtension::ClientAfterServerInfo { user, password }.into())
			}
		}
	}

	fn build_from_bytes(
		&mut self,
		mut bytes: Bytes,
		_role: Role,
	) -> Result<AnyProtocolExtension, WispError> {
		match self {
			Self::ServerBeforeClientInfo { endpoint, required } => {
				let user_len = bytes.get_u8();

				let endpoint = endpoint.clone();
				let user = std::str::from_utf8(&bytes.split_to(user_len as usize))?.to_string();
				let pw_len = bytes.get_u16_le();
				let password = std::str::from_utf8(&bytes.split_to(pw_len as usize))?.to_string();

				*self = Self::ServerAfterClientInfo {
					endpoint: endpoint.clone(),
					required: *required,
				};

				Ok(PuterPasswordProtocolExtension::ServerAfterClientInfo {
					endpoint: endpoint,
					chosen_user: user,
					chosen_password: password,
				}
				.into())
			}
			Self::ClientBeforeServerInfo { creds } => {
				let required = bytes.get_u8() != 0;

				*self = Self::ClientAfterServerInfo {
					creds: creds.clone(),
					required,
				};

				Ok(PuterPasswordProtocolExtension::ClientBeforeServerInfo.into())
			}
			Self::ClientAfterServerInfo { .. } | Self::ServerAfterClientInfo { .. } => {
				Err(WispError::ExtensionImplNotSupported)
			}
		}
	}
}
