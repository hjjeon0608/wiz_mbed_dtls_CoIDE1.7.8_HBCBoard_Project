/*
 * Server certificate registration
 */
#define CERTIFICATE selfsignedcert
#define HOST_NAME	"localhost"

/*
 * smtp.gmail.com
 */
const char	certs_gmail[] =	\
"-----BEGIN CERTIFICATE-----\r\n"									\
"MIIFODCCBCCgAwIBAgIQUT+5dDhwtzRAQY0wkwaZ/zANBgkqhkiG9w0BAQsFADCB\r\n"  \
"yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\r\n"  \
"ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\r\n"  \
"U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\r\n"  \
"ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\r\n"  \
"aG9yaXR5IC0gRzUwHhcNMTMxMDMxMDAwMDAwWhcNMjMxMDMwMjM1OTU5WjB+MQsw\r\n"  \
"CQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24xHzAdBgNV\r\n"  \
"BAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxLzAtBgNVBAMTJlN5bWFudGVjIENs\r\n"  \
"YXNzIDMgU2VjdXJlIFNlcnZlciBDQSAtIEc0MIIBIjANBgkqhkiG9w0BAQEFAAOC\r\n"  \
"AQ8AMIIBCgKCAQEAstgFyhx0LbUXVjnFSlIJluhL2AzxaJ+aQihiw6UwU35VEYJb\r\n"  \
"A3oNL+F5BMm0lncZgQGUWfm893qZJ4Itt4PdWid/sgN6nFMl6UgfRk/InSn4vnlW\r\n"  \
"9vf92Tpo2otLgjNBEsPIPMzWlnqEIRoiBAMnF4scaGGTDw5RgDMdtLXO637QYqzu\r\n"  \
"s3sBdO9pNevK1T2p7peYyo2qRA4lmUoVlqTObQJUHypqJuIGOmNIrLRM0XWTUP8T\r\n"  \
"L9ba4cYY9Z/JJV3zADreJk20KQnNDz0jbxZKgRb78oMQw7jW2FUyPfG9D72MUpVK\r\n"  \
"Fpd6UiFjdS8W+cRmvvW1Cdj/JwDNRHxvSz+w9wIDAQABo4IBYzCCAV8wEgYDVR0T\r\n"  \
"AQH/BAgwBgEB/wIBADAwBgNVHR8EKTAnMCWgI6Ahhh9odHRwOi8vczEuc3ltY2Iu\r\n"  \
"Y29tL3BjYTMtZzUuY3JsMA4GA1UdDwEB/wQEAwIBBjAvBggrBgEFBQcBAQQjMCEw\r\n"  \
"HwYIKwYBBQUHMAGGE2h0dHA6Ly9zMi5zeW1jYi5jb20wawYDVR0gBGQwYjBgBgpg\r\n"  \
"hkgBhvhFAQc2MFIwJgYIKwYBBQUHAgEWGmh0dHA6Ly93d3cuc3ltYXV0aC5jb20v\r\n"  \
"Y3BzMCgGCCsGAQUFBwICMBwaGmh0dHA6Ly93d3cuc3ltYXV0aC5jb20vcnBhMCkG\r\n"  \
"A1UdEQQiMCCkHjAcMRowGAYDVQQDExFTeW1hbnRlY1BLSS0xLTUzNDAdBgNVHQ4E\r\n"  \
"FgQUX2DPYZBV34RDFIpgKrL1evRDGO8wHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnz\r\n"  \
"Qzn6Aq8zMTMwDQYJKoZIhvcNAQELBQADggEBAF6UVkndji1l9cE2UbYD49qecxny\r\n"  \
"H1mrWH5sJgUs+oHXXCMXIiw3k/eG7IXmsKP9H+IyqEVv4dn7ua/ScKAyQmW/hP4W\r\n"  \
"Ko8/xabWo5N9Q+l0IZE1KPRj6S7t9/Vcf0uatSDpCr3gRRAMFJSaXaXjS5HoJJtG\r\n"  \
"QGX0InLNmfiIEfXzf+YzguaoxX7+0AjiJVgIcWjmzaLmFN5OUiQt/eV5E1PnXi8t\r\n"  \
"TRttQBVSK/eHiXgSgW7ZTaoteNTCLD0IX4eRnh8OsN4wUmSGiaqdZpwOdgyA8nTY\r\n"  \
"Kvi4Os7X1g8RvmurFPW9QaAiY4nxug9vKWNmLT+sjHLF+8fk1A/yO0+MKcc=\r\n"  \
"-----END CERTIFICATE-----\r\n";

/*
 * mosquitto server(222.98.173.239)
 *
 */

const char	mosquitto_broker[] =	\
"-----BEGIN CERTIFICATE-----\r\n" 										\
"MIIDpzCCAo+gAwIBAgIJANXTM7couqP2MA0GCSqGSIb3DQEBDQUAMGoxFzAVBgNV\r\n"  \
"BAMMDkFuIE1RVFQgYnJva2VyMRYwFAYDVQQKDA1Pd25UcmFja3Mub3JnMRQwEgYD\r\n"  \
"VQQLDAtnZW5lcmF0ZS1DQTEhMB8GCSqGSIb3DQEJARYSbm9ib2R5QGV4YW1wbGUu\r\n"  \
"bmV0MB4XDTE1MTAxMzExMDEyM1oXDTMyMTAwODExMDEyM1owajEXMBUGA1UEAwwO\r\n"  \
"QW4gTVFUVCBicm9rZXIxFjAUBgNVBAoMDU93blRyYWNrcy5vcmcxFDASBgNVBAsM\r\n"  \
"C2dlbmVyYXRlLUNBMSEwHwYJKoZIhvcNAQkBFhJub2JvZHlAZXhhbXBsZS5uZXQw\r\n"  \
"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDufb7rBXRFpswywzlF7lXd\r\n"  \
"U/Ml2++Nnp80EkeMDAYKGoWnqM7F/cAiej+p2+5ovTcF4FWBKTCIC62YzrfiNlUl\r\n"  \
"ae/ZwrkVrP5hDgrxyaZkoURKQa3c7BSkxF0wU2QNaOKxeTFk7JPYOSxwrbaWjBQM\r\n"  \
"Zlnrsv0vxkyn1QctO8uRyJJrio9kT3J1pdKUdMoMn0e7tGEvJRio9fQ6WD16inOM\r\n"  \
"jjN9RrZhGpWE5unCmM+ENNCN0eknSOnmcDPXRFBsTQRBFcWJ9A4qZByKWakTg0DF\r\n"  \
"sOa29XBVijsTrIpVdJrviesCdbIpuZ/iM8xeuhVRIGmk8HHOvv0NHOeI6PgTTw0H\r\n"  \
"AgMBAAGjUDBOMB0GA1UdDgQWBBRHmW4T3assj+/m54fvvOlCVdG1NTAfBgNVHSME\r\n"  \
"GDAWgBRHmW4T3assj+/m54fvvOlCVdG1NTAMBgNVHRMEBTADAQH/MA0GCSqGSIb3\r\n"  \
"DQEBDQUAA4IBAQC0Av3UF0OftbPavNHooutq6yNh7o53GLeTqLpod1BuiP9V+KUy\r\n"  \
"FsHR+9lmm/iIK9jcr5RFbvcVSKkbQcyvxrWth4ebfLxe0dQbNmSsVf28D7QELqh6\r\n"  \
"e17nKU8r7otT7BmtP5mMLct2IrFvi8JEfPcJ5CGI6BCVYSQAP7aW6aPLHpA5c77f\r\n"  \
"lV8d1N1NN/q6uEV/nz97CJIWZhkA3YY+Aa0uA8AQ27HdtiZDWMWvdkhioFbype6Z\r\n"  \
"QxYsVUPI3HQqSWlpeWwPrM4OiqnjzMbuhnwqr9vxJI6LC6sBV/5VQdyBfxI6ReqJ\r\n"  \
"lDbqVJI4oeEV3YvL9ODBI1Hh9VJlcPWyvxCq\r\n"  \
"-----END CERTIFICATE-----\r\n";
/*
 * api.twitter.com
 */

const char	api_twitter_com[] =	\
"-----BEGIN CERTIFICATE-----\r\n"  \
"MIIF7DCCBNSgAwIBAgIQbsx6pacDIAm4zrz06VLUkTANBgkqhkiG9w0BAQUFADCB\r\n"  \
"yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL\r\n"  \
"ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp\r\n"  \
"U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW\r\n"  \
"ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0\r\n"  \
"aG9yaXR5IC0gRzUwHhcNMTAwMjA4MDAwMDAwWhcNMjAwMjA3MjM1OTU5WjCBtTEL\r\n"  \
"MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW\r\n"  \
"ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTswOQYDVQQLEzJUZXJtcyBvZiB1c2UgYXQg\r\n"  \
"aHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL3JwYSAoYykxMDEvMC0GA1UEAxMmVmVy\r\n"  \
"aVNpZ24gQ2xhc3MgMyBTZWN1cmUgU2VydmVyIENBIC0gRzMwggEiMA0GCSqGSIb3\r\n"  \
"DQEBAQUAA4IBDwAwggEKAoIBAQCxh4QfwgxF9byrJZenraI+nLr2wTm4i8rCrFbG\r\n"  \
"5btljkRPTc5v7QlK1K9OEJxoiy6Ve4mbE8riNDTB81vzSXtig0iBdNGIeGwCU/m8\r\n"  \
"f0MmV1gzgzszChew0E6RJK2GfWQS3HRKNKEdCuqWHQsV/KNLO85jiND4LQyUhhDK\r\n"  \
"tpo9yus3nABINYYpUHjoRWPNGUFP9ZXse5jUxHGzUL4os4+guVOc9cosI6n9FAbo\r\n"  \
"GLSa6Dxugf3kzTU2s1HTaewSulZub5tXxYsU5w7HnO1KVGrJTcW/EbGuHGeBy0RV\r\n"  \
"M5l/JJs/U0V/hhrzPPptf4H1uErT9YU3HLWm0AnkGHs4TvoPAgMBAAGjggHfMIIB\r\n"  \
"2zA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3NwLnZlcmlz\r\n"  \
"aWduLmNvbTASBgNVHRMBAf8ECDAGAQH/AgEAMHAGA1UdIARpMGcwZQYLYIZIAYb4\r\n"  \
"RQEHFwMwVjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cudmVyaXNpZ24uY29tL2Nw\r\n"  \
"czAqBggrBgEFBQcCAjAeGhxodHRwczovL3d3dy52ZXJpc2lnbi5jb20vcnBhMDQG\r\n"  \
"A1UdHwQtMCswKaAnoCWGI2h0dHA6Ly9jcmwudmVyaXNpZ24uY29tL3BjYTMtZzUu\r\n"  \
"Y3JsMA4GA1UdDwEB/wQEAwIBBjBtBggrBgEFBQcBDARhMF+hXaBbMFkwVzBVFglp\r\n"  \
"bWFnZS9naWYwITAfMAcGBSsOAwIaBBSP5dMahqyNjmvDz4Bq1EgYLHsZLjAlFiNo\r\n"  \
"dHRwOi8vbG9nby52ZXJpc2lnbi5jb20vdnNsb2dvLmdpZjAoBgNVHREEITAfpB0w\r\n"  \
"GzEZMBcGA1UEAxMQVmVyaVNpZ25NUEtJLTItNjAdBgNVHQ4EFgQUDURcFlNEwYJ+\r\n"  \
"HSCrJfQBY9i+eaUwHwYDVR0jBBgwFoAUf9Nlp8Ld7LvwMAnzQzn6Aq8zMTMwDQYJ\r\n"  \
"KoZIhvcNAQEFBQADggEBAAyDJO/dwwzZWJz+NrbrioBL0aP3nfPMU++CnqOh5pfB\r\n"  \
"WJ11bOAdG0z60cEtBcDqbrIicFXZIDNAMwfCZYP6j0M3m+oOmmxw7vacgDvZN/R6\r\n"  \
"bezQGH1JSsqZxxkoor7YdyT3hSaGbYcFQEFn0Sc67dxIHSLNCwuLvPSxe/20majp\r\n"  \
"dirhGi2HbnTTiN0eIsbfFrYrghQKlFzyUOyvzv9iNw2tZdMGQVPtAhTItVgooazg\r\n"  \
"W+yzf5VK+wPIrSbb5mZ4EkrZn0L74ZjmQoObj49nJOhhGbXdzbULJgWOw27EyHW4\r\n"  \
"Rs/iGAZeqa6ogZpHFt4MKGwlJ7net4RYxh84HqTEy2Y=\r\n"  \
"-----END CERTIFICATE-----\r\n";

const char	graph_facebook_com[] = \
"-----BEGIN CERTIFICATE-----\r\n"  \
"MIIEsTCCA5mgAwIBAgIQBOHnpNxc8vNtwCtCuF0VnzANBgkqhkiG9w0BAQsFADBs\r\n"  \
"MQswCQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3\r\n"  \
"d3cuZGlnaWNlcnQuY29tMSswKQYDVQQDEyJEaWdpQ2VydCBIaWdoIEFzc3VyYW5j\r\n"  \
"ZSBFViBSb290IENBMB4XDTEzMTAyMjEyMDAwMFoXDTI4MTAyMjEyMDAwMFowcDEL\r\n"  \
"MAkGA1UEBhMCVVMxFTATBgNVBAoTDERpZ2lDZXJ0IEluYzEZMBcGA1UECxMQd3d3\r\n"  \
"LmRpZ2ljZXJ0LmNvbTEvMC0GA1UEAxMmRGlnaUNlcnQgU0hBMiBIaWdoIEFzc3Vy\r\n"  \
"YW5jZSBTZXJ2ZXIgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC2\r\n"  \
"4C/CJAbIbQRf1+8KZAayfSImZRauQkCbztyfn3YHPsMwVYcZuU+UDlqUH1VWtMIC\r\n"  \
"Kq/QmO4LQNfE0DtyyBSe75CxEamu0si4QzrZCwvV1ZX1QK/IHe1NnF9Xt4ZQaJn1\r\n"  \
"itrSxwUfqJfJ3KSxgoQtxq2lnMcZgqaFD15EWCo3j/018QsIJzJa9buLnqS9UdAn\r\n"  \
"4t07QjOjBSjEuyjMmqwrIw14xnvmXnG3Sj4I+4G3FhahnSMSTeXXkgisdaScus0X\r\n"  \
"sh5ENWV/UyU50RwKmmMbGZJ0aAo3wsJSSMs5WqK24V3B3aAguCGikyZvFEohQcft\r\n"  \
"bZvySC/zA/WiaJJTL17jAgMBAAGjggFJMIIBRTASBgNVHRMBAf8ECDAGAQH/AgEA\r\n"  \
"MA4GA1UdDwEB/wQEAwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIw\r\n"  \
"NAYIKwYBBQUHAQEEKDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5kaWdpY2Vy\r\n"  \
"dC5jb20wSwYDVR0fBEQwQjBAoD6gPIY6aHR0cDovL2NybDQuZGlnaWNlcnQuY29t\r\n"  \
"L0RpZ2lDZXJ0SGlnaEFzc3VyYW5jZUVWUm9vdENBLmNybDA9BgNVHSAENjA0MDIG\r\n"  \
"BFUdIAAwKjAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29tL0NQ\r\n"  \
"UzAdBgNVHQ4EFgQUUWj/kK8CB3U8zNllZGKiErhZcjswHwYDVR0jBBgwFoAUsT7D\r\n"  \
"aQP4v0cB1JgmGggC72NkK8MwDQYJKoZIhvcNAQELBQADggEBABiKlYkD5m3fXPwd\r\n"  \
"aOpKj4PWUS+Na0QWnqxj9dJubISZi6qBcYRb7TROsLd5kinMLYBq8I4g4Xmk/gNH\r\n"  \
"E+r1hspZcX30BJZr01lYPf7TMSVcGDiEo+afgv2MW5gxTs14nhr9hctJqvIni5ly\r\n"  \
"/D6q1UEL2tU2ob8cbkdJf17ZSHwD2f2LSaCYJkJA69aSEaRkCldUxPUd1gJea6zu\r\n"  \
"xICaEnL6VpPX/78whQYwvwt/Tv9XBZ0k7YXDK/umdaisLRbvfXknsuvCnQsH6qqF\r\n"  \
"0wGjIChBWUMo0oHjqvbsezt3tkBigAVBRQHvFwY+3sAzm2fTYS5yh+Rp/BIAV0Ae\r\n"  \
"cPUeybQ=\r\n"  \
"-----END CERTIFICATE-----\r\n";

const char	selfsignedcert[] = \
"-----BEGIN CERTIFICATE-----\r\n"  \
"MIIDnjCCAoYCCQCz0o4F7H00LDANBgkqhkiG9w0BAQsFADCBkDELMAkGA1UEBhMC\r\n"  \
"S1IxDjAMBgNVBAgMBVNlb3VsMRAwDgYDVQQHDAdCdW5kYW5nMQ8wDQYDVQQKDAZX\r\n"  \
"SVpuZXQxDjAMBgNVBAsMBVBldGVyMRgwFgYDVQQDDA9XSVpuZXRJUHNlYy5jb20x\r\n"  \
"JDAiBgkqhkiG9w0BCQEWFXBldGVyQFdJWm5ldElQc2VjLmNvbTAeFw0xNjAzMDcw\r\n"  \
"NTQ5MTRaFw0xNzAzMDcwNTQ5MTRaMIGQMQswCQYDVQQGEwJLUjEOMAwGA1UECAwF\r\n"  \
"U2VvdWwxEDAOBgNVBAcMB0J1bmRhbmcxDzANBgNVBAoMBldJWm5ldDEOMAwGA1UE\r\n"  \
"CwwFUGV0ZXIxGDAWBgNVBAMMD1dJWm5ldElQc2VjLmNvbTEkMCIGCSqGSIb3DQEJ\r\n"  \
"ARYVcGV0ZXJAV0labmV0SVBzZWMuY29tMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\r\n"  \
"MIIBCgKCAQEAtsL5Lkn0RLBE+zlkVIlvwwPC263q9apjT08y2mBnr3uVuHJKoKbt\r\n"  \
"OoAZikrM/ueiBYSJUJZzJ7Go2i/ZZxM+7TVu/U8M3QK+gXSHXNuRvEr0yeWeruWe\r\n"  \
"dKzAzoZRVnPv9IofOThK8g7l+qpdu38Q9RS359mH+5coEZ85Z2SdH51yegrrLaKp\r\n"  \
"4vYTFe88IVAhIqoXHBg4U9QxacD+FlR9IhdlnwX7GEctcVhMkNy55cjMZacjR4pX\r\n"  \
"AfOah2US0QqbDZwYZvSi7Txr4Eu7z/ZTz1gy1Cbb1OHbKJQ/Q7yyvRhEFvQtoNq+\r\n"  \
"Gqlt2LQEy/kBmZPp+lubH351kI9bLzPW4wIDAQABMA0GCSqGSIb3DQEBCwUAA4IB\r\n"  \
"AQCT2R7H8f4NgFrc4a7E0I8uVqFJeBm3mWIVX9RyXRpNwoUj6hxkIxxGTBUEdGw4\r\n"  \
"50baTsvCY6Fcr54fXnA1CpHdpeA//BAGuUwOh//NmRbfCaNFkYZULZMCGujumJbG\r\n"  \
"ySl9uA3e9GfGrKZJryToBxZHVBTeNxHQAA+XT9UHpO0J+hJwCg3dp3RgZipJyHOj\r\n"  \
"k90+nG1Ghg/JUEFcEmV87+5EbO6T2VE2mKRe/wj9QzoFtidC4W1Z8pesWELNnVMN\r\n"  \
"EkbRTahx1xRDe/EB4SvF4RFFy9J5NofRzVmnkMTNXOFk/8PG4FqWsbAnQqnxCRWc\r\n"  \
"b17bk4svHM+n0K5lcIlW5Cu7\r\n"  \
"-----END CERTIFICATE-----\r\n";


