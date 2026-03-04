import shared from "../../../../test/shared/browsers.prod.mts";

shared.define = {
  "process.env.MOCKED": JSON.stringify("false"),
  "process.env.METADATA": JSON.stringify("https://metadata.web3auth.io"),
};

export default shared;
