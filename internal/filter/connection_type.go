package filter

var connectionStateName = map[connectionState]string{
	connectionStateHTTP:                      "http",
	connectionStateUpgradeWebsocketRequested: "websocket upgrade requested",
	connectionStateWebsocketConnection:       "websocket connection",
}

type connectionState int

const (
	connectionStateHTTP connectionState = iota
	connectionStateUpgradeWebsocketRequested
	connectionStateWebsocketConnection
)

func (connectionState connectionState) String() string {
	return connectionStateName[connectionState]
}

func (connectionState connectionState) IsHttp() bool {
	return connectionState == connectionStateHTTP
}

func (connectionState connectionState) IsWebsocket() bool {
	return connectionState == connectionStateWebsocketConnection
}

func (connectionState connectionState) IsWebsocketUpgradeRequested() bool {
	return connectionState == connectionStateUpgradeWebsocketRequested
}
