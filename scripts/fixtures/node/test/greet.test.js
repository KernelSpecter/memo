const test = require("node:test");
const assert = require("node:assert");
const { greet } = require("../src/greet");

test("greet", () => {
  assert.strictEqual(greet("memo"), "hello, memo");
});
