/*
Copyright 2020 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package attestlib

import (
	"encoding/base64"
	"testing"
)

const goodPayload = "good payload"

// RSA Public Keys
const rsa2048PubKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Vf+g3iALHB5GHz2sTMm
VmemVMio8iAgIXDhfdJmAJJCUG61vH7ZFOJNWwVPiX2HE4iC8quLT3a2W5h81OiD
Y2FXfD5vZB0lycXNZoasyhUlC4TFsL01tgh7W7WN5iBDlwxY13bcgv79SIbroz/C
+kS1+cqu4GQXmEHLYFg80pQVe7ssBaQ3qxA0HL0heXJfM0Ye40Aw3aC430h92f2a
5JgY8JEqRTtYgh3VVuqzm3L4QvSWiHzfB29BXCB0GstFK448aYkk2RPI6Q1LkoT7
NiCquPVF1EYnUXKrC+ANoWr/l7ldEJ7V4vpo+9EClnXcxAzq/knqeN5WdM6iPYny
qwIDAQAB
-----END PUBLIC KEY-----`

const rsa3072PubKey = `-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA174cl1EgPn1w/4r1OTNy
O5ViVEtjPV1Bl2xXA/4EOcVyvztdwovJriC2sry+gW7WS/YraS6BXTY328daY7u5
OYAHnr/NiF3BoAzbAYMpHU6otMiAlGADrgevESj5XKUp4+XuiYxdOPH7pqgHaZ0+
ZIvp08vH+xXsY1+WqA3TBsKxkCwTmWGUSy/j2Gml6XHgX1SywJGJ9VEI/5wACExX
3NYHx+OXBS5XyjFzIoBxFiuA4g8FRHcTw1uulX98Rt/WTwTjesMeWaB7mOxgK03A
rTOil11+/Wgboow3V93B5pdNMvVjkahYHvkjYkj/HJRuXUKidZANhBWEewpdHDkK
+NXa8BlxcbkzcO2DvXGRu1g0emVInoIEN+/1fz4ab/mTWUGgs9QX+INChlSV3EBz
5I6mXbc3fE4EW2W9KASIPKIpF1HBaF58B//W+XAy7mxhuSfg23/mkf4SI9ZVM82s
rBmJaTmRgKWbZXNaf4yH+RhyGF1CsBN2uLrt667Swxv3AgMBAAE=
-----END PUBLIC KEY-----`

const rsa4096PubKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAte+CWFUwOwyD/VBaK55o
qxTMOX34Y3evVlCY9iDXwYbi+yDgSgjB4K2sTvyV6ztQEBWzReNX3GG7WkPWkHVB
OIssRgtVUtNnngQkgoOwJWxGf0k1R/NrXRsRMReyuW1zT6iftVhClexf5eBLtmqy
7hXCpy7NNx9486YpF8KJGa1wrV3Ko3R1qHYjGgKd/fjtQ5CcFUZUYgmYQeIkeDO1
DiQOSYS2xnkUTfV2aHIgFUlrxdU2M50He5Z/jSE49/9IXQac599y2m6irVaVT6VM
vY6mxSRGgRx3hkoajVrxd3MglIFLO8/FfrOGwZg9bZFIlgHjUiFPPKbn8bSyldMZ
xNj36t7YC2ZpN6XGzeBnnLfBW1GjGomk3G1eyBUCwRk9nHt9Dsqr/xEauMocHcfA
EfEm8/fwcp5MB8GOZ3l8p9Rs38yoBFzVbj2SeicFoQTnHe4DrtMvBzGyKsiaKszV
5UJAPyqm7zPph/Ck++NRQDmJvkhLXcs7QrUG2TBA7veqaLzrU88jY3RDKSIbNtLA
xBrmQID1ms7TVrCcB6nWrxHJc3FhTP6q/lUL0ziG8fOND9oW6P0YxaXj+1qIxn45
x2j5oDwsx8ig4/V23Yuofvji2j/VYAY/KAkKJOXqfozbmlMNUCpN6HuQ5yakVFgW
XanFz99rw4kZ0z70ziCBp68CAwEAAQ==
-----END PUBLIC KEY-----`

// Signtature created with rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, dgst[:]) where dgst is the hashed value of goodPlaintext.
const rsa2048_256Sig = "DDFzpubahBxVPnKdImjEx8qWssgSezVQm7iQt_VaKhi5SuTpNnryIejmBjOvnDG2u94veHvBANwHPTaH7_m6L07N73yVHaOG86BI6z5cVG-jCriLP5acYKosbsSW9rL7ei8IyVR1JEn0LVaIfNjd4LNMQA5fgTIPQ6zqFfqqbFGAKyTFs6qZoz6JVD253-jpSt_2gBPTbav-wubI2ZxMEtsn6OJZbJf08wGjCwdqs_8qM6-N4DaMlkDooQc3qUyeG3PtL0Oc8wv663YNgB0lMwPfFSTiiHWfqlaA5ipWYxR1zabp3edczblEhAzb7t6Eq3LxdbMJV0GsCiFuqur-PA"
const rsa3072_256Sig = "yI39TrSAFxGsMnQeiS-NQvju4EclmoMOL-Y4jCG11jLC2fgIfXY2SQt0dLTLRk_QyZfLOWngNmW5I3OpoPeVpFjKyakVeU54vpqnXasWMmQUHl_5ymTGufxy-zq4pufVm87ljaXhXX5NOAAprj5ZPrXIhzd9NF2jjZ0uj6MCXlsX0t97Xjd9aaP_TUwodCF36l151Lf3de4VQVZvxek-TxRb4Fqc1zLQJknR2rZBI_KmEGAI7stjt9Nsx50sDBLoFK5LipqoZMwyebJQoE8r9etgu-baq_iL3tek97gDOJtsItQmSLfgVtHZs7LBcrspXxZgPiABKUbwSDKcuiQrmq-4auDR5QD2_v89QpnGM42L4iiBk4oOVSzdGBjrVF2RzFBglYbNOkeDsrS2ZEkSu7TTiwuMf8BNb8qHrXeFkyNH2O7-ot-7A6675k9S2lEbr3GuUoZaHLXjik7g8VgPRABewoCeEsK62Je8alCNy02THa6Lc3Z4F2kOfK_jK3AZ"
const rsa4096_256Sig = "ghBqtgXjuj-9NkVuLk21_mZcatc1oxCd6lKWnfd51pYXe_FTqpni8trYqQCC3VmKOsaA5lid5BQulO8P8tR_lr0kd2JpGQqeorjzKqFWkf8nKk9ZOaofq5Hn96jEXR09xNcyva2E4aq_Ly98wcDUY1EvhuI1EokwSqPubpPPC0Lr_KlKWiF2gRzluyfLbajjkjq43n5sMuEU02S_c2-s78sFVbho7KC3QE7ykhu_-DNglWQ5-XMvgdfV9g5H-jJLMLLRjkVqFFazrNS9yYovY5hOrxZ0nA2cOt9WDzCaly22mTozDarKqEPkp8fCh0yAcBUHijfeQETr1MA1eCh67ekNC-RlqXfQUIagqlaGC9uuGBWKeXB3py-Cfi5rX0SHr4lmh7wfiFqBT5UMvINbSWu3GX6XxK6bAP9PoRyeNulxUKOU5z6MgDbhTzirQNuqk4LEMPwYHfrU1tEfP5F0sEtxl6IB3nIwQyW23ut1dgBxQDLLIkCqAv91RsIy5smTzqGAAAy47jyNGkK-D4ASylPXfZMsAbYoBKQPqqBoRNz3-gTWKnV7uWh-dJx4Lwb60LAlZ8T4C6KaQ5lBsCNHcSvaidwZKk6vB4rTgY3qlZvmsVjU-3Fg1-PPomamqms9Df1w5gE91msZW0JgfX1DwSe8PG6tKH8eg5yaupqAEFs"

// Signtature created with rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA512, dgst[:]) where dgst is the hashed value of goodPlaintext.
const rsa4096_512Sig = "AAgs8EX5jJ56OcI7V5guArvPbOyLGRyK79_F_1DuubBY-2Q_PdiiTJ2qcfs1TCrVudrJsO-SrUL1sgNpUMl44fcCXHw2SvIecPmdHkkIU6IFtTrBXwie-WUsQqr7kLkhjWejoGdI7bYVzPLT_k_RE8hMDBl1CaQuCMcESVdTqremN2TAax4j4PvbaFYyWDEDM9gGf5ylMzXO6gOw-3HZOrcQ44zNjNhcu6W6xs730TRyGbE9a3q3XyDjNCiikT6U36eds6-m5rDPNMvqin0YJda5ZDOdxge2f9HOu0PHR7WKPtF-65SVHM58c6qzuJHr7jLqG_PkKnBTlwLHZH3G6kZDwl3IepkOkw_esuX-BdzRdS7eFhpr5c20N5VfOYlU_itnEFs850iUkkQ_48vdQC55-hbkYxH9qbYSMbfiVrLxmiI3f5pXmX3MJv1LrHA3XDtBi0dhQpJVYyMfZZmmwZt-oJk-tIzoZb0vBDP5ucCUaiKReiRhCTw07VAH-UY2f5cvRhZ0CW8aZMhkH7JxT1JETov6mRo-kmMsRLKqkTLDjBkrl3YNtRKMQTauCFYCMME4bF4qJxPPBres3LlbAKyNMT0b9V6bpBUrQv247rawl2DEiDUZMDswKN3_kGMfOzW9iCetQYtBRxfkLygocm49UZO3wuNg-deT7Sya7jo"

// Signtature created with rsa.SignPSS(rand.Reader, privateKey, crypto.SHA256, dgst[:], nil) where dgst is the hashed value of goodPlaintext.
const rsa2048_256PssSig = "fPdgFVY9OZSDTHqt7a74gFdBokpPuiUntWtPk0W2Bnsbbc2LLAG9qvt-z-WrKQ4IKHjq8Grm-asuePTKvIKRrLETgth2tXNT2yRFplmR3F6rwRbIZrcxEtjWLI2d0n0FVNdjdu7ozlJRWSQV666VP3Sq8BnZE6T5KpoSu4FYgNnE_12Y-DBzSmxcMSuEemO7-LBda0aGU8VxLpa5e0dq614BshF56yYLKIgjeNxBZmvTRSxn6sFdNiSdWed2KWsLAiUgwgcfIEQo4wuAXRia3nlW8ti0lsr3nDPURKdc51-jSCF-Ng9iTETlZeoeT5b2RIPRVPvs4mujrkfYJ_Mphw"
const rsa3072_256PssSig = "tsqYI8HtyqBr_EypDD8hDh9GrrAI9u3KCfwBGodttQdp-u0W4U5LCN0cXSraJG0iSjoJqjv2y-yZ_t_czQm4q5PnkiViRUd_TEwf47XiJDh4Yr2EUnjEQehkKJtyJvqAPiIG5jtuqXBaeNHHwPzw594CbrwGTjqdvOaZXtIFu7qsbdI_1jzS2Uv2kPZLCwuA4TKuWCLHOEj8A5_uJ7g8o08dS_l-dH7fh_b7_dGDrbZIBfKZAYlwSaXGqSp1MOJ1-xqVn1ClIP6LP8roU_jwo66fTm5JikLe8JoNX6EOrlK26tUPAZBfpbXK0ii2LwjSCyfti2OX9NrR4MvOY5lm8qADmdYBEh52KeukxOuS3ZlgSHgvmdD8qwNl2cFpooEj2nCihb_BiDOmka8prZUQIq-cvdAh-Wq_RBcPM4LEB02FC8O48KlH0feDHaVwqozytYxKCYnHpq6AJcovsZ2MWpx3MhXHs9Yf97nzdn-0ocEF6nhybY-xmBACoNCz9FUQ"
const rsa4096_256PssSig = "YiiWdkQklQ0d5Bn6yvk3QxuRTDrvdzuL-IZ8SNjQDEEfU5_30oZBUkc-UyJKANCYRcfDRwX4TqckkobAerlYlvhQeQEB_1RPztlDN_9_oRN3jzgK55MkRQ7sldr1QgjMUxlqL6CMjOnnI2dCu8z33Oj0U2i7_WqOfn8QuBC3VtOXVUWc-LRAJWowpWAuJGqlLrhbeanmMRgxiBngEq1RCM8o9WoDtDsUwc69_kXBxs0fUDl0dfnz51FcY5LHwKILD5hEPYY1d-c1O-gb_BBl-cf7TQUFVcORLRL41Y-dnnsDo-4M_EHsk9a4SErKT4leNYpSGo5sk612JUHs9pSHUK0nDksKzzWXp04-E4g4gnhiSDUcuer9KBt_MIULR3-_Zd0kmSrmdCPo1FnPS89MaoqN0x-lBIpjfmjlFQ6mKaO1iXxSypuieTErq8duZ1-5TZ-1l2wfpuKIB2UqURLOqwf8oZFu-ykbIahS3OgTx563vzFxMx5aTFWtbA8YhgaMnShOD4lHW1KuI4cRd5UGV0vfL8YkbTrwqcxB2GwA-BsXXVc-U63GKo2qwhzV6SPLOcdjwA87DU48ZyWNkHYH4qPMaLMWAdBl--WMzzuIlOc69BWcJLVpIlHwGb9_tp2ZVQmZkf0e59uG9BaSX1SqMapfFS2pntqayEhWKtwAWew"

// Signtature created with rsa.SignPSS(rand.Reader, privateKey, crypto.SHA512, dgst[:], nil) where dgst is the hashed value of goodPlaintext.
const rsa4096_512PssSig = "f8gSD9u6XkwsqZYEaQtYdha8MwKNtwhtJRdD4YW-hQkTwPZa3dyj7PRulAI_MQWKCANFAVsqh2sHAP7atBpO79Evccqng_XBTsW6VYxMmHE4R3V7_dBKFHPdt3YE66kufrAy5TzYdAtQTikxT2C8SUb6L_KJg4Byavsx1sPbeRLEQBj8a_glBqfgqmr_4i06hfv9c9a1MGye8SSsaxYfURiGeSRs_mTep5CyE0Xze_ByZeoEEZjYsrpaFVzVsvViNHNcrP1GxsBL8GCz1oPcmAUD1P1nRT_X1kYycuodqpX4Pca3OpBp7kGRdXdBm6UugXLYPoHHZd6ks4NXRrTcY9OieE8s3UmQIwG6cJN4o4j8fmZF68iC50_vlA5rGBtxsdRCcmL9Q9LBZKgKH-FRHagrixAm-T3Ahbf-VpRDodgjz01Lwz8cVMfcZJ3SeHPoAvgOO4fGRRTQMpzKmDWNBlx2Nj3WXyIOeJEkg_2kJ7GEt5FspiXPGZsmU1XIJxblCZ_h1dpbQf0ow4l_fmQyAv6q2Gxw0J2I3TmaISsQfwHCpD07FBcp4hLrVrVdRIeRLvhYPcWUaWYn09whhwwpa0s2AJeKEKplbJuJRX322kyfzFsiAAcECWQEc0fz9gNw9aEaWhuUKevS_NpKx7rLZjkFzAYLQKQDme2mbm7OkC8"

// ECDSA Public Keys
const ec256PubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEi6Jhqhr28Lzd2ouX/pFLAV3gXCQ9
uq6nyHps7WrRsA7gcpjVT9H2mybHFsTm6nt4mhEeTTiYNeu86gNdT0LnkA==
-----END PUBLIC KEY-----`

const ec384PubKey = `-----BEGIN PUBLIC KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEyM9sE/BBKqJsjqz7uoYZEfP9D62PNB0k
4YB53Txb5ryOr1KOrF0ujyRFz6forthkkmEJC95vpZHQToX3fn2Ez0s2VSrOV7pS
900NKIazIqV+IBucdMFTKMvgh5MQDAbo
-----END PUBLIC KEY-----`

const ec521PubKey = `-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQB/ooeXAbotIupXGPH3MR8/tHB8fCT
6hIO4VmndSUG7sfyeD7CAusyZrscx5a9VdO4vnZyxmT8VW42LLSy9ydAR1IBPrqR
iCD5lC7gvz/9MQR4gkNlz7qyXNtDjLdUqbIOtUaRQLNmXea2UBH644v03siONBR+
su9oz4mHH2NSHLwmlS4=
-----END PUBLIC KEY-----`

// Signatures created with ecdsa.Sign(rand.Reader, privateKey, dgst[:]) where dgst is the hashed value of goodPlaintext
const ec256Sig = "MEQCIF3vDDK3-lYuBJLS5YePGYZ1Fih9a1MHkBISa9Yg-32rAiBzNkzKswSiNUHXoTPxBj8XYNrQBZC-jfD2dq-2Ke_zDg"
const ec384Sig = "MGUCMFMH3lMmZrM4qPIegBZxb64fBkfS4jCeZ5XCVw0BYqC27PdTjoTyLaLlBWJvLpS6hAIxAJWsDJLdrhNyVhp9zMLHtFB4J_Q_QrZNh2tflxtVNFwWU3_JDKBr4g7vQFNIfQ880A"
const ec521Sig = "MIGIAkIAofN81k5oSaXMYtoClAYQyVNv2aN1jJtCoIJKeQ0x4bGZAZdpGX8TMdUbiOjfjOedkOE55i94qb4UXzyuvGT0OegCQgC6-8kEXa72KL9upGhzQRzoZOku0EsbyOkwQOHDtj-HZxUG-lGsBhQsc2ABqXoiK07ZmdvMd_t358oVKl_isjEx5w"

const badKey = "malformed key"

const extraDataKey = `-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAte+CWFUwOwyD/VBaK55o
qxTMOX34Y3evVlCY9iDXwYbi+yDgSgjB4K2sTvyV6ztQEBWzReNX3GG7WkPWkHVB
OIssRgtVUtNnngQkgoOwJWxGf0k1R/NrXRsRMReyuW1zT6iftVhClexf5eBLtmqy
7hXCpy7NNx9486YpF8KJGa1wrV3Ko3R1qHYjGgKd/fjtQ5CcFUZUYgmYQeIkeDO1
DiQOSYS2xnkUTfV2aHIgFUlrxdU2M50He5Z/jSE49/9IXQac599y2m6irVaVT6VM
vY6mxSRGgRx3hkoajVrxd3MglIFLO8/FfrOGwZg9bZFIlgHjUiFPPKbn8bSyldMZ
xNj36t7YC2ZpN6XGzeBnnLfBW1GjGomk3G1eyBUCwRk9nHt9Dsqr/xEauMocHcfA
EfEm8/fwcp5MB8GOZ3l8p9Rs38yoBFzVbj2SeicFoQTnHe4DrtMvBzGyKsiaKszV
5UJAPyqm7zPph/Ck++NRQDmJvkhLXcs7QrUG2TBA7veqaLzrU88jY3RDKSIbNtLA
xBrmQID1ms7TVrCcB6nWrxHJc3FhTP6q/lUL0ziG8fOND9oW6P0YxaXj+1qIxn45
x2j5oDwsx8ig4/V23Yuofvji2j/VYAY/KAkKJOXqfozbmlMNUCpN6HuQ5yakVFgW
XanFz99rw4kZ0z70ziCBp68CAwEAAQ==
-----END PUBLIC KEY-----
with some extra stuff`

func TestVerifyDetached(t *testing.T) {

	tcs := []struct {
		name          string
		signature     string
		pubkey        []byte
		signingAlg    SignatureAlgorithm
		payload       []byte
		expectedError bool
	}{
		{
			name:          "good RsaSignPkcs12048Sha256 signature",
			signature:     rsa2048_256Sig,
			pubkey:        []byte(rsa2048PubKey),
			signingAlg:    RsaSignPkcs12048Sha256,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "good RsaSignPkcs13072Sha256 signature",
			signature:     rsa3072_256Sig,
			pubkey:        []byte(rsa3072PubKey),
			signingAlg:    RsaSignPkcs13072Sha256,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "good RsaSignPkcs14096Sha256 signature",
			signature:     rsa4096_256Sig,
			pubkey:        []byte(rsa4096PubKey),
			signingAlg:    RsaSignPkcs14096Sha256,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "good RsaSignPkcs14096Sha512 signature",
			signature:     rsa4096_512Sig,
			pubkey:        []byte(rsa4096PubKey),
			signingAlg:    RsaSignPkcs14096Sha512,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "good RsaPss2048Sha256 signature",
			signature:     rsa2048_256PssSig,
			pubkey:        []byte(rsa2048PubKey),
			signingAlg:    RsaPss2048Sha256,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "good RsaPss3072Sha256 signature",
			signature:     rsa3072_256PssSig,
			pubkey:        []byte(rsa3072PubKey),
			signingAlg:    RsaPss3072Sha256,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "good RsaPss4096Sha256 signature",
			signature:     rsa4096_256PssSig,
			pubkey:        []byte(rsa4096PubKey),
			signingAlg:    RsaPss4096Sha256,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "good RsaPss4096Sha512 signature",
			signature:     rsa4096_512PssSig,
			pubkey:        []byte(rsa4096PubKey),
			signingAlg:    RsaPss4096Sha512,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "good EcdsaP256Sha256 signature",
			signature:     ec256Sig,
			pubkey:        []byte(ec256PubKey),
			signingAlg:    EcdsaP256Sha256,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "good EcdsaP384Sha384 signature",
			signature:     ec384Sig,
			pubkey:        []byte(ec384PubKey),
			signingAlg:    EcdsaP384Sha384,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "good EcdsaP521Sha512 signature",
			signature:     ec521Sig,
			pubkey:        []byte(ec521PubKey),
			signingAlg:    EcdsaP521Sha512,
			payload:       []byte(goodPayload),
			expectedError: false,
		},
		{
			name:          "bad pub key",
			signature:     rsa2048_256Sig,
			pubkey:        []byte(badKey),
			signingAlg:    RsaSignPkcs12048Sha256,
			payload:       []byte(goodPayload),
			expectedError: true,
		},
		{
			name:          "pub key with extra data",
			signature:     rsa2048_256Sig,
			pubkey:        []byte(extraDataKey),
			signingAlg:    RsaSignPkcs12048Sha256,
			payload:       []byte(goodPayload),
			expectedError: true,
		},
	}

	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			decodedSig, decodeErr := base64.RawURLEncoding.DecodeString(tc.signature)
			if decodeErr != nil {
				t.Fatalf("error base64 decoding signature: %v", decodeErr)
			}
			err := verifyDetached(decodedSig, tc.pubkey, tc.signingAlg, tc.payload)
			if tc.expectedError {
				if err == nil {
					t.Errorf("verifyDetached(...)=nil, expected non-nil")
				}
			} else {
				if err != nil {
					t.Errorf("verifyDetached(...)=%v, expected nil", err)
				}
			}
		})
	}
}

func TestCreateDetachedSignature(t *testing.T) {
	tcs := []struct {
		name          string
		key           []byte
		alg           SignatureAlgorithm
		expectedError bool
	}{
		{
			name:          "create rsa signature success",
			key:           []byte(rsa2048PrivateKey),
			alg:           RsaSignPkcs12048Sha256,
			expectedError: false,
		}, {
			name:          "create ecdsa signature success",
			key:           []byte(ec256PrivateKey),
			alg:           EcdsaP256Sha256,
			expectedError: false,
		},
		{
			name:          "rsa key with ecdsa alg",
			key:           []byte(rsa2048PrivateKey),
			alg:           EcdsaP256Sha256,
			expectedError: true,
		}, {
			name:          "ecdsa key with rsa alg",
			key:           []byte(ec256PrivateKey),
			alg:           RsaSignPkcs12048Sha256,
			expectedError: true,
		}, {
			name:          "unknown singature algorithm",
			key:           []byte(rsa2048PrivateKey),
			alg:           UnknownSigningAlgorithm,
			expectedError: true,
		},
	}
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			privKey, err := parsePkixPrivateKeyPem(tc.key)
			if err != nil {
				t.Fatalf("failed to parse private key %v", err)
			}
			_, err = createDetachedSignature(privKey, []byte(payload), tc.alg)
			if tc.expectedError {
				if err == nil {
					t.Errorf("createDetachedSignature(...)=nil, expected non-nil")
				}
			} else {
				if err != nil {
					t.Errorf("createDetachedSignature(...)=%v, expected nil", err)
				}
			}
		})
	}
}
