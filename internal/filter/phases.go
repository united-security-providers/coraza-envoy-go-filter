package filter

type phase int

const (
	PhaseUnknown phase = iota
	PhaseRequestHeader
	PhaseRequestBody
	PhaseResponseHeader
	PhaseResponseBody
)

func (p phase) String() string {
	switch p {
	case PhaseRequestHeader:
		return "request_header"
	case PhaseRequestBody:
		return "request_body"
	case PhaseResponseHeader:
		return "response_header"
	case PhaseResponseBody:
		return "response_body"
	default:
		return "unknown"
	}
}
