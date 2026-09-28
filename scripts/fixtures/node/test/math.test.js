const test = require("node:test");
const assert = require("node:assert");
const { add, mul } = require("../src/math");

test("add", () => {
  assert.strictEqual(add(2, 3), 5);
});

test("mul", () => {
  assert.strictEqual(mul(4, 5), 20);
});
