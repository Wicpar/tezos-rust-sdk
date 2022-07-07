use {
    crate::client::TezosRPCContext, crate::error::Error, crate::protocol_rpc::block::BlockID,
    num_bigint::BigInt,
};

fn path<S: AsRef<str>>(chain_id: S, block_id: &BlockID, contract: S) -> String {
    format!("{}/balance", super::path(chain_id, block_id, contract))
}

/// A builder to construct the properties of a request to access the balance of a contract.
#[derive(Clone, Copy)]
pub struct RPCRequestBuilder<'a> {
    ctx: &'a TezosRPCContext,
    chain_id: &'a str,
    block_id: &'a BlockID,
    contract: &'a str,
}

impl<'a> RPCRequestBuilder<'a> {
    pub fn new(ctx: &'a TezosRPCContext, contract: &'a str) -> Self {
        RPCRequestBuilder {
            ctx,
            chain_id: &ctx.chain_id,
            block_id: &BlockID::Head,
            contract: contract,
        }
    }

    /// Modify chain identifier to be used in the request.
    pub fn chain_id(&mut self, chain_id: &'a str) -> &mut Self {
        self.chain_id = chain_id;

        self
    }

    /// Modify the block identifier to be used in the request.
    pub fn block_id(&mut self, block_id: &'a BlockID) -> &mut Self {
        self.block_id = block_id;

        self
    }

    pub async fn send(self) -> Result<BigInt, Error> {
        let path = self::path(self.chain_id, self.block_id, self.contract);

        let balance: String = self.ctx.http_client.get(path.as_str()).await?;

        Ok(balance.parse::<BigInt>()?)
    }
}

/// Access the balance of a contract.
///
/// [`GET /chains/<chain_id>/blocks/<block>/context/contracts/<contract_id>/balance`](https://tezos.gitlab.io/active/rpc.html#get-block-id-context-contracts-contract-id-balance)
pub fn get<'a>(ctx: &'a TezosRPCContext, address: &'a str) -> RPCRequestBuilder<'a> {
    RPCRequestBuilder::new(ctx, address)
}

#[cfg(test)]
mod tests {
    use {
        crate::client::TezosRPC,
        crate::error::Error,
        crate::{constants::DEFAULT_CHAIN_ALIAS, protocol_rpc::block::BlockID},
        httpmock::prelude::*,
        num_bigint::BigInt,
    };

    #[tokio::test]
    async fn test_get_balance() -> Result<(), Error> {
        let server = MockServer::start();
        let rpc_url = server.base_url();

        let contract_address = "tz1bLUuUBWtJqFX2Hz3A3whYE5SNTAGHjcpL";
        let expected_balance = BigInt::from(9999999999999999999 as u64);
        let block_id = BlockID::Head;

        server.mock(|when, then| {
            when.method(GET).path(super::path(
                &DEFAULT_CHAIN_ALIAS.to_string(),
                &block_id,
                &contract_address.to_string(),
            ));
            then.status(200)
                .header("content-type", "application/json")
                .json_body(format!("{}", expected_balance));
        });

        let client = TezosRPC::new(rpc_url.as_str());
        let balance = client
            .get_contract_balance(&contract_address.to_string())
            .block_id(&block_id)
            .send()
            .await?;

        assert_eq!(balance, expected_balance);

        Ok(())
    }
}