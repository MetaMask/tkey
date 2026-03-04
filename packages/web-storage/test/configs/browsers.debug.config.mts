import shared from "../../../../test/shared/browsers.debug.mts";

shared.define = {
  "process.env.MOCKED": JSON.stringify(process.env.MOCKED ?? "false"),
  "process.env.METADATA": JSON.stringify(process.env.METADATA ?? "http://localhost:5051"),
};

export default shared;
