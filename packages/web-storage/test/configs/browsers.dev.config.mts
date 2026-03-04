import shared from "../../../../test/shared/browsers.dev.mts";

shared.define = {
  "process.env.MOCKED": JSON.stringify("false"),
  "process.env.METADATA": JSON.stringify("http://localhost:5051"),
};

export default shared;
