package iso

type ControlResult struct {
	ControlID string
	RiskScore float64
	Passed    bool
	Source    string
}

type ISOReport struct {
	Controls []ControlResult
	Total    float64
}

// Maps raw scanner outputs → ISO 27001 / 27002 controls

func MapControls(
	phishing float64,
	password float64,
	wifi float64,
	email float64,
	session float64,
	privilege float64,
	usb float64,
	browser float64,
	data float64,
) ISOReport {

	controls := []ControlResult{

		// A.6.3.1 Awareness
		{
			ControlID: "A.6.3.1",
			RiskScore: phishing,
			Passed:    phishing < 50,
			Source:    "phishing",
		},

		// A.5.17 Authentication
		{
			ControlID: "A.5.17",
			RiskScore: password,
			Passed:    password < 50,
			Source:    "password",
		},

		// A.8.20 Network security
		{
			ControlID: "A.8.20",
			RiskScore: wifi,
			Passed:    wifi < 50,
			Source:    "wifi",
		},

		// A.8.23 Email security
		{
			ControlID: "A.8.23",
			RiskScore: email,
			Passed:    email < 50,
			Source:    "email",
		},

		// A.5.15 Access control
		{
			ControlID: "A.5.15",
			RiskScore: session,
			Passed:    session < 50,
			Source:    "session",
		},

		// A.5.18 Privileged access
		{
			ControlID: "A.5.18",
			RiskScore: privilege,
			Passed:    privilege < 50,
			Source:    "privilege",
		},

		// A.8.12 Data leakage prevention
		{
			ControlID: "A.8.12",
			RiskScore: usb,
			Passed:    usb < 50,
			Source:    "usb",
		},

		// A.8.25 Browser security (custom mapping)
		{
			ControlID: "A.8.25",
			RiskScore: browser,
			Passed:    browser < 50,
			Source:    "browser",
		},

		// A.8.10 Information deletion / leakage
		{
			ControlID: "A.8.10",
			RiskScore: data,
			Passed:    data < 50,
			Source:    "data",
		},
	}

	total := 0.0
	for _, c := range controls {
		total += c.RiskScore
	}

	return ISOReport{
		Controls: controls,
		Total:    total / float64(len(controls)),
	}
}
