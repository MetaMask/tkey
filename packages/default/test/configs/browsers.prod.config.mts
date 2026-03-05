import shared from "../../../../test/shared/browsers.prod.mts";

shared.test!.testTimeout = 0;
shared.test!.env = {
  MOCKED: "false",
  METADATA: "https://node-1.dev-node.web3auth.io/metadata",
};

export default shared;
