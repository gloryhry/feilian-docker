# Isolated runtime fixture

This context contains **no official FeiLian client and no VPN implementation**.
It is supplied explicitly as the `test_fixtures` BuildKit named context for the
`mock` target. The fake service only listens on local 31055/31056; the fake GUI
shows an unmistakable test label. Neither is evidence of official gRPC, login,
enterprise routing or account compatibility.

Production builds must use the `production` target and the reviewed installer
context instead. Official-client smoke and release checks must reject images
whose `io.feilian.client.kind` label is not `official`.
