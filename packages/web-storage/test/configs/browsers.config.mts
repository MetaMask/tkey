import shared from "../../../../test/shared/browsers.mocked.mts";

shared.define = {
  "process.env.MOCKED": JSON.stringify("true"),
};

export default shared;
