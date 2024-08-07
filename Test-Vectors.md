# Test Vectors for the Specification

## Protocol Signature

### Signing Keys

```json5
{
  "secret-key":
    "dGVzdDEyMzR0ZXN0MTIzNHRlc3QxMjM0dGVzdDEyMzRObZcG9vSYBviV1W5sLO_PQcxNzNHxUYXjiy_jvxUUsw",
  "public-key":
    "Tm2XBvb0mAb4ldVubCzvz0HMTczR8VGF44sv478VFLM"
}
```

### Protocol Message

```json5
{
  "@context": "https:\/\/github.com\/fedi-e2ee\/public-key-directory\/v1",
  "action": "InvalidExampleAction",
  "message": {
    "actor": "https:\/\/example.com\/users\/alice"
  }
}
```

### Encoded Data To Be Signed (hex-encoded)

```terminal
0600000000000000080000000000000040636f6e74657874340000000000000068747470733a2f2f6769746875622e636f6d2f666564692d653265652f7075626c69632d6b65792d6469726563746f72792f76310600000000000000616374696f6e1400000000000000496e76616c69644578616d706c65416374696f6e07000000000000006d6573736167652f000000000000007b226163746f72223a2268747470733a5c2f5c2f6578616d706c652e636f6d5c2f75736572735c2f616c696365227d
```

### Expected Signature

```terminal
OfoR5JJ3JMFxgTatOfOgLt5jHupqIHUHjHaQOgnB44eIM6ehXXLx0_jbU9QgHHLa_Ok9sLWoquMni5FOFzsgAg
```
