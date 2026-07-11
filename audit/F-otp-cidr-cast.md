# F-otp-cidr-cast: OTP validate cast source_cidr::cidr, throwing on operator host-bits CIDRs

- Severity: medium
- Status: Verified-Fixed
- Area: otp

The schema stores CIDRs via lenient ::inet (host bits allowed), but validate cast ::cidr (strict) → a valid OTP with a host-bits CIDR errored instead of validating (self-found during review). **Fixed:** both sides cast ::inet + a fail-closed onError. Regression: AuthServicesIT.otpSourceCidrWithHostBitsDoesNotThrow + malformedSourceIpFailsClosed.
