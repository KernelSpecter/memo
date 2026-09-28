// Connect-only "is the server up?" check: no data is sent, so only memo's
// ConnectEx detection can tell this command used the network.
const net = require("net");
const srv = net.createServer().listen(0, "127.0.0.1", () => {
  const c = net.connect(srv.address().port, "127.0.0.1", () => {
    console.log("server is up");
    c.destroy();
    srv.close();
  });
});
