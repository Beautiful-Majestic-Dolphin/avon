use avon_config::TlsArgs;
use avon_protocol::v2::ca_service_client::CaServiceClient;
use avon_protocol::v2::{
    Chain, Credential, Crl, Csr, Empty, IssueDeviceRequest, RevokeRequest, Uuid as PbUuid,
};
use tonic::transport::{Channel, Endpoint};
use tonic::Status;
use uuid::Uuid;

#[derive(Clone)]
pub struct CaClient(CaServiceClient<Channel>);

impl CaClient {
    pub async fn connect(url: &str, server_name: &str, tls: &TlsArgs) -> anyhow::Result<Self> {
        let channel = Endpoint::from_shared(url.to_string())?
            .tls_config(avon_tls::client_tls_config(tls, server_name)?)?
            .connect()
            .await?;
        Ok(Self(CaServiceClient::new(channel)))
    }

    pub async fn issue_device(
        &self,
        tenant: Uuid,
        device: Uuid,
        csr: Csr,
        kind: u32,
        sans: Vec<String>,
    ) -> Result<(Credential, Vec<u8>), Status> {
        let resp = self
            .0
            .clone()
            .issue_device_credential(IssueDeviceRequest {
                tenant_id: Some(PbUuid {
                    value: tenant.as_bytes().to_vec(),
                }),
                device_id: Some(PbUuid {
                    value: device.as_bytes().to_vec(),
                }),
                csr: Some(csr),
                kind,
                sans,
            })
            .await?
            .into_inner();
        let cred = resp
            .credential
            .ok_or_else(|| Status::internal("ca returned no credential"))?;
        Ok((cred, resp.serial))
    }

    pub async fn chain(&self) -> Result<Chain, Status> {
        Ok(self.0.clone().get_chain(Empty {}).await?.into_inner())
    }

    pub async fn crl(&self) -> Result<Crl, Status> {
        Ok(self.0.clone().current_crl(Empty {}).await?.into_inner())
    }

    pub async fn revoke(&self, serial: Vec<u8>, reason: &str) -> Result<Crl, Status> {
        Ok(self
            .0
            .clone()
            .revoke(RevokeRequest {
                serial,
                reason: reason.into(),
            })
            .await?
            .into_inner())
    }
}
