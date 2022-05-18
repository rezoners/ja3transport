package main

import (
	"crypto/sha256"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	tls "github.com/Danny-Dasilva/utls"
)

const (
	chrome  = "chrome"  //chrome User agent enum
	firefox = "firefox" //firefox User agent enum
)

func parseUserAgent(userAgent string) string {
	switch {
	case strings.Contains(strings.ToLower(userAgent), "chrome"):
		return chrome
	case strings.Contains(strings.ToLower(userAgent), "firefox"):
		return firefox
	default:
		return chrome
	}

}


// greasePlaceholder is a random value (well, kindof '0x?a?a) specified in a
// random RFC.
const greasePlaceholder = 0x0a0a

// ErrExtensionNotExist is returned when an extension is not supported by the library
type ErrExtensionNotExist string

// Error is the error value which contains the extension that does not exist
func (e ErrExtensionNotExist) Error() string {
	return fmt.Sprintf("Extension does not exist: %s\n", string(e))
}

// extMap maps extension values to the TLSExtension object associated with the
// number. Some values are not put in here because they must be applied in a
// special way. For example, "10" is the SupportedCurves extension which is also
// used to calculate the JA3 signature. These JA3-dependent values are applied
// after the instantiation of the map.


// NewTransport creates an http.Transport which mocks the given JA3 signature when HTTPS is used
func NewTransport(ja3 string) (*http.Transport, error) {
	return NewTransportWithConfig(ja3, &tls.Config{})
}

// NewTransportWithConfig creates an http.Transport object given a utls.Config
func NewTransportWithConfig(ja3 string, config *tls.Config) (*http.Transport, error) {
	spec, err := stringToSpec(ja3)
	if err != nil {
		return nil, err
	}

	dialtls := func(network, addr string) (net.Conn, error) {
		dialConn, err := net.Dial(network, addr)
		if err != nil {
			return nil, err
		}

		config.ServerName = strings.Split(addr, ":")[0]

		uTLSConn := tls.UClient(dialConn, config, tls.HelloCustom)
		if err := uTLSConn.ApplyPreset(spec); err != nil {
			return nil, err
		}
		if err := uTLSConn.Handshake(); err != nil {
			return nil, err
		}
		return uTLSConn, nil
	}

	return &http.Transport{DialTLS: dialtls}, nil
}

// stringToSpec creates a ClientHelloSpec based on a JA3 string
func stringToSpec(ja3 string) (*tls.ClientHelloSpec, error) {

	extMap := genMap()
	tokens := strings.Split(ja3, ",")

	version := tokens[0]
	ciphers := strings.Split(tokens[1], "-")
	extensions := strings.Split(tokens[2], "-")
	curves := strings.Split(tokens[3], "-")
	if len(curves) == 1 && curves[0] == "" {
		curves = []string{}
	}
	pointFormats := strings.Split(tokens[4], "-")
	if len(pointFormats) == 1 && pointFormats[0] == "" {
		pointFormats = []string{}
	}
	// parse curves
	var targetCurves []tls.CurveID
	targetCurves = append(targetCurves, tls.CurveID(tls.GREASE_PLACEHOLDER)) //append grease for Chrome browsers
	for _, c := range curves {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		targetCurves = append(targetCurves, tls.CurveID(cid))
		// if cid != uint64(utls.CurveP521) {
		// CurveP521 sometimes causes handshake errors
		// }
	}
	extMap["10"] = &tls.SupportedCurvesExtension{Curves: targetCurves}

	// parse point formats
	var targetPointFormats []byte
	for _, p := range pointFormats {
		pid, err := strconv.ParseUint(p, 10, 8)
		if err != nil {
			return nil, err
		}
		targetPointFormats = append(targetPointFormats, byte(pid))
	}
	extMap["11"] = &tls.SupportedPointsExtension{SupportedPoints: targetPointFormats}

	// set extension 43
	vid64, err := strconv.ParseUint(version, 10, 16)
	if err != nil {
		return nil, err
	}
	vid := uint16(vid64)
	// extMap["43"] = &utls.SupportedVersionsExtension{
	// 	Versions: []uint16{
	// 		utls.VersionTLS12,
	// 	},
	// }

	// build extenions list
	var exts []tls.TLSExtension
	//Optionally Add Chrome Grease Extension
	if "test" == chrome {
		exts = append(exts, &tls.UtlsGREASEExtension{})
	}
	for _, e := range extensions {
		te, ok := extMap[e]
		if !ok {
			return nil, raiseExtensionError(e)
		}
		// //Optionally add Chrome Grease Extension
		if e == "21" && "test" == chrome {
			exts = append(exts, &tls.UtlsGREASEExtension{})
		}
		exts = append(exts, te)
	}
	//Add this back in if user agent is chrome and no padding extension is given
	// if parsedUserAgent == chrome {
	// 	exts = append(exts, &utls.UtlsGREASEExtension{})
	// 	exts = append(exts, &utls.UtlsPaddingExtension{GetPaddingLen: utls.BoringPaddingStyle})
	// }
	// build SSLVersion
	// vid64, err := strconv.ParseUint(version, 10, 16)
	// if err != nil {
	// 	return nil, err
	// }

	// build CipherSuites
	var suites []uint16
	//Optionally Add Chrome Grease Extension
	if "test" == chrome {
		suites = append(suites, tls.GREASE_PLACEHOLDER)
	}
	for _, c := range ciphers {
		cid, err := strconv.ParseUint(c, 10, 16)
		if err != nil {
			return nil, err
		}
		suites = append(suites, uint16(cid))
	}
	_ = vid
	return &tls.ClientHelloSpec{
		// TLSVersMin:         vid,
		// TLSVersMax:         vid,
		CipherSuites:       suites,
		CompressionMethods: []byte{0},
		Extensions:         exts,
		GetSessionID:       sha256.Sum256,
	}, nil
}
func genMap() (extMap map[string]tls.TLSExtension) {
	extMap = map[string]tls.TLSExtension{
		"0": &tls.SNIExtension{},
		"5": &tls.StatusRequestExtension{},
		// These are applied later
		// "10": &tls.SupportedCurvesExtension{...}
		// "11": &tls.SupportedPointsExtension{...}
		"13": &tls.SignatureAlgorithmsExtension{
			SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				tls.ECDSAWithSHA1,
				tls.PKCS1WithSHA1,
			},
		},
		"16": &tls.ALPNExtension{
			AlpnProtocols: []string{"h2", "http/1.1"},
		},
		"18": &tls.SCTExtension{},
		"21": &tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
		"22": &tls.GenericExtension{Id: 22}, // encrypt_then_mac
		"23": &tls.UtlsExtendedMasterSecretExtension{},
		"27": &tls.FakeCertCompressionAlgsExtension{
			Methods: []tls.CertCompressionAlgo{tls.CertCompressionBrotli},
		},
		"28": &tls.FakeRecordSizeLimitExtension{}, //Limit: 0x4001
		"35": &tls.SessionTicketExtension{},
		"34": &tls.GenericExtension{Id: 34},
		"41": &tls.GenericExtension{Id: 41}, //FIXME pre_shared_key
		"43": &tls.SupportedVersionsExtension{Versions: []uint16{
			tls.GREASE_PLACEHOLDER,
			tls.VersionTLS13,
			tls.VersionTLS12,
			tls.VersionTLS11,
			tls.VersionTLS10}},
		"44": &tls.CookieExtension{},
		"45": &tls.PSKKeyExchangeModesExtension{Modes: []uint8{
			tls.PskModeDHE,
		}},
		"49": &tls.GenericExtension{Id: 49}, // post_handshake_auth
		"50": &tls.GenericExtension{Id: 50}, // signature_algorithms_cert
		"51": &tls.KeyShareExtension{KeyShares: []tls.KeyShare{
			{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
			{Group: tls.X25519},

			// {Group: utls.CurveP384}, known bug missing correct extensions for handshake
		}},
		"30032": &tls.GenericExtension{Id: 0x7550, Data: []byte{0}}, //FIXME
		"13172": &tls.NPNExtension{},
		"17513": &tls.ApplicationSettingsExtension{
			SupportedALPNList: []string{
				"h2",
			},
		},
		"65281": &tls.RenegotiationInfoExtension{
			Renegotiation: tls.RenegotiateOnceAsClient,
		},
	}
	return

}



func urlToHost(target *url.URL) *url.URL {
	if !strings.Contains(target.Host, ":") {
		if target.Scheme == "http" {
			target.Host = target.Host + ":80"
		} else if target.Scheme == "https" {
			target.Host = target.Host + ":443"
		}
	}
	return target
}

type errExtensionNotExist struct {
	Context string
}

func (w *errExtensionNotExist) Error() string {
	return fmt.Sprintf("Extension {{ %s }} is not Supported by CycleTLS please raise an issue", w.Context)
}

func raiseExtensionError(info string) *errExtensionNotExist {
	return &errExtensionNotExist{
		Context: info,
	}
}
