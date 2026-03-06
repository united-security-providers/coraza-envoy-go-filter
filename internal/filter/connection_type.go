package filter

var connectionStateName = map[connectionState]string{
	connectionStateHttp:                      "http",
	connectionStateHttpTunnel:                "http tunnel",
	connectionStateUpgradeWebsocketRequested: "websocket upgrade requested",
	connectionStateWebsocketConnection:       "websocket connection",
}

type connectionState int

const (
	connectionStateHttp connectionState = iota
	connectionStateHttpTunnel
	connectionStateUpgradeWebsocketRequested
	connectionStateWebsocketConnection
)

func (connectionState connectionState) String() string {
	return connectionStateName[connectionState]
}

func (connectionState connectionState) IsHttp() bool {
	return connectionState == connectionStateHttp
}

func (connectionState connectionState) IsWebsocket() bool {
	return connectionState == connectionStateWebsocketConnection
}

func (connectionState connectionState) IsWebsocketUpgradeRequested() bool {
	return connectionState == connectionStateUpgradeWebsocketRequested
}
