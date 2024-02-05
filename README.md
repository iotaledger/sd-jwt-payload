<!-- This READM is based on the BEST-README-Template (https://github.com/othneildrew/Best-README-Template) -->
<div id="top"></div>
<!--
*** Thanks for checking out the Best-README-Template. If you have a suggestion
*** that would make this better, please fork the repo and create a pull request
*** or simply open an issue with the tag "enhancement".
*** Don't forget to give the project a star!
*** Thanks again! Now go create something AMAZING! :D
-->



<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
<!-- [![Contributors][contributors-shield]][contributors-url] -->
<!-- [![Forks][forks-shield]][forks-url] -->
<!-- [![Stargazers][stars-shield]][stars-url] -->
<!-- [![Issues][issues-shield]][issues-url] -->
[![Apache 2.0 license][license-shield]][license-url]
[![Discord][discord-shield]][discord-url]
[![StackExchange][stackexchange-shield]][stackexchange-url]
<!-- Add additional Badges. Some examples >
![Format Badge](https://github.com/iotaledger/template/workflows/Format/badge.svg "Format Badge")
![Audit Badge](https://github.com/iotaledger/template/workflows/Audit/badge.svg "Audit Badge")
![BuildBadge](https://github.com/iotaledger/template/workflows/Build/badge.svg "Build Badge")
![Test Badge](https://github.com/iotaledger/template/workflows/Test/badge.svg "Test Badge")
![Coverage Badge](https://coveralls.io/repos/github/iotaledger/template/badge.svg "Coverage Badge")

<!-- ABOUT THE PROJECT -->

# SD-JWT Reference implementation

Rust implementation of the [Selective Disclosure for JWTs (SD-JWT) **version 07**](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html)

## Overview

This library supports 
* **Encoding**:
  - creating disclosers and replacing values in objects and arrays with the digest of their disclosure. 
  - Adding decoys to objects and arrays.
* **Decoding**  
  - Recursively replace digests in objects and arrays with their corresponding disclosure value.

`Sha-256` hash function is shipped by default, encoding/decoding with other hash functions is possible. 

## Getting started
Include the library in your `cargo.toml`.

```bash
[dependencies]
sd-jwt-payload = { version = "0.2.0" }
```

## Examples

See [sd_jwt.rs](./examples/sd_jwt.rs) for a runnable example.

## Usage

This library consists of the major structs:
1. [`SdObjectEncoder`](./src/encoder.rs): creates SD objects.
2. [`SdObjectDecoder`](./src/decoder.rs): decodes SD objects.
3. [`Disclosure`](./src/disclosure.rs): used by the `SdObjectEncoder` and `SdObjectDecoder` to represent a disclosure.
3. [`SdJwt`](./src/sd_jwt.rs): creates/parses SD-JWTs.
4. [`Hasher`](./src/hasher.rs): a trait to provide hash functions to the encoder/decoder.
5. [`Sha256Hasher`](./src/hasher.rs): implements `Hasher` for the `Sha-256` hash function.


### Encoding
Any JSON object can be encoded


```rust
  let object = json!({
    "given_name": "John",
    "family_name": "Doe",
    "address": {
      "street_address": "123 Main St",
      "region": "Anystate",
    },
    "phone": [
      "+49 123456",
      "+49 234567"
    ]
  });
```


```rust
  let mut encoder: SdObjectEncoder = object.try_into()?;
```
This creates a stateful encoder with `Sha-256` hash function by default to create disclosure digests. 

*Note: `SdObjectEncoder` is generic over `Hasher` which allows custom encoding with other hash functions.*

The encoder can encode any of the object's values or array elements, using the `conceal` method. Suppose the value of `street_address` should be selectively disclosed as well as the value of `address` and the first `phone` value.


```rust
  let disclosure1 = encoder.conceal("/address/street_address"], None)?;
  let disclosure2 = encoder.conceal("/address", None)?;
  let disclosure3 = encoder.conceal("/phone/0", None)?;
```

```
"WyJHaGpUZVYwV2xlUHE1bUNrVUtPVTkzcXV4WURjTzIiLCAic3RyZWV0X2FkZHJlc3MiLCAiMTIzIE1haW4gU3QiXQ"
"WyJVVXVBelg5RDdFV1g0c0FRVVM5aURLYVp3cU13blUiLCAiYWRkcmVzcyIsIHsicmVnaW9uIjoiQW55c3RhdGUiLCJfc2QiOlsiaHdiX2d0eG01SnhVbzJmTTQySzc3Q194QTUxcmkwTXF0TVVLZmI0ZVByMCJdfV0"
"WyJHRDYzSTYwUFJjb3dvdXJUUmg4OG5aM1JNbW14YVMiLCAiKzQ5IDEyMzQ1NiJd"
```
*Note: the `conceal` method takes a [JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901) to determine the element to conceal inside the JSON object.*


The encoder also supports adding decoys. For instance, the amount of phone numbers and the amount of claims need to be hidden.

```rust
  encoder.add_decoys("/phone", 3).unwrap(); //Adds 3 decoys to the array `phone`.
  encoder.add_decoys("", 6).unwrap(); // Adds 6 decoys to the top level object.
```

Add the hash function claim.
```rust
  encoder.add_sd_alg_property(); // This adds "_sd_alg": "sha-256"
```

Now `encoder.object()?` will return the encoded object.

```json
{
  "given_name": "John",
  "family_name": "Doe",
  "phone": [
    {
      "...": "eZVn0KkQm_T8x-x57VxYt-_MmNG91Sh34E-bZEnNfWY"
    },
    "+49 234567",
    {
      "...": "KAiJIx0tktQRXBxZSBVVld9298bZIp2WkpkDYDa3CWQ"
    },
    {
      "...": "CBKARPh6sdTCJyliZ7pBOYzix7Z4Bb4yRh0EykHX2Uw"
    },
    {
      "...": "oi1KgsYXgqBFXUXvbVaHSGYYaWhkB5RL55T90Gl_5s0"
    }
  ],
  "_sd": [
    "Jj5jBeGEawY6vRvmHDg55EjeAIP8FVhWEV2FczhUXrY",
    "8eqphBPJyCBgUJhNWNP7ci-Y79N615wpZQrxi5D4ju8",
    "_hOU5puJjNzSBhK0bwh3h8_b6H6nN7vd_7I0uTp80Mo",
    "G_tH70MrfCkVM0HhsH9REObIt1Ei19477y6CEsS0Zlo",
    "zP56MeH0ryjzqh9Kadrb5C9Z2BE2FWg8nb3g0rR3LSA",
    "dgfVW11ip9OOyVi8M4h1RjXK8akw7ICeMQkjUwSI6iU",
    "Bx33mOyTF5-w8gRS5yL4YQ4dig44V3lmHxk1WRss_7U"
  ],
  "_sd_alg": "sha-256"
}
```

*Note: no JWT claims like `exp` or `iat` are added. If necessary, these need to be added and validated manually.*

### Creating SD-JWT

Since creating JWTs is outside the scope of this library, see [sd_jwt.rs example](./examples/sd_jwt.rs) where `josekit` is used to create `jwt` with the object above as the claim set.

Create SD-JWT

```rust
  let sd_jwt: SdJwt = SdJwt::new(jwt, disclosures.clone(), None);
  let sd_jwt: String = sd_jwt.presentation();
```

```
eyJ0eXAiOiJTRC1KV1QiLCJhbGciOiJIUzI1NiJ9.eyJnaXZlbl9uYW1lIjoiSm9obiIsImZhbWlseV9uYW1lIjoiRG9lIiwicGhvbmUiOlt7Ii4uLiI6ImVaVm4wS2tRbV9UOHgteDU3VnhZdC1fTW1ORzkxU2gzNEUtYlpFbk5mV1kifSwiKzQ5IDIzNDU2NyIseyIuLi4iOiJLQWlKSXgwdGt0UVJYQnhaU0JWVmxkOTI5OGJaSXAyV2twa0RZRGEzQ1dRIn0seyIuLi4iOiJDQktBUlBoNnNkVENKeWxpWjdwQk9Zeml4N1o0QmI0eVJoMEV5a0hYMlV3In0seyIuLi4iOiJvaTFLZ3NZWGdxQkZYVVh2YlZhSFNHWVlhV2hrQjVSTDU1VDkwR2xfNXMwIn1dLCJfc2QiOlsiSmo1akJlR0Vhd1k2dlJ2bUhEZzU1RWplQUlQOEZWaFdFVjJGY3poVVhyWSIsIjhlcXBoQlBKeUNCZ1VKaE5XTlA3Y2ktWTc5TjYxNXdwWlFyeGk1RDRqdTgiLCJfaE9VNXB1SmpOelNCaEswYndoM2g4X2I2SDZuTjd2ZF83STB1VHA4ME1vIiwiR190SDcwTXJmQ2tWTTBIaHNIOVJFT2JJdDFFaTE5NDc3eTZDRXNTMFpsbyIsInpQNTZNZUgwcnlqenFoOUthZHJiNUM5WjJCRTJGV2c4bmIzZzByUjNMU0EiLCJkZ2ZWVzExaXA5T095Vmk4TTRoMVJqWEs4YWt3N0lDZU1Ra2pVd1NJNmlVIiwiQngzM21PeVRGNS13OGdSUzV5TDRZUTRkaWc0NFYzbG1IeGsxV1Jzc183VSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.knTqw4FMCplHoMu7mfiix7dv4lIjYgRIn-tmuemAhbY~WyJHaGpUZVYwV2xlUHE1bUNrVUtPVTkzcXV4WURjTzIiLCAic3RyZWV0X2FkZHJlc3MiLCAiMTIzIE1haW4gU3QiXQ~WyJVVXVBelg5RDdFV1g0c0FRVVM5aURLYVp3cU13blUiLCAiYWRkcmVzcyIsIHsicmVnaW9uIjoiQW55c3RhdGUiLCJfc2QiOlsiaHdiX2d0eG01SnhVbzJmTTQySzc3Q194QTUxcmkwTXF0TVVLZmI0ZVByMCJdfV0~WyJHRDYzSTYwUFJjb3dvdXJUUmg4OG5aM1JNbW14YVMiLCAiKzQ5IDEyMzQ1NiJd~
```

### Decoding

Parse the SD-JWT string to extract the JWT and the disclosures in order to decode the claims and construct the disclosed values.

*Note: Validating the signature of the JWT and extracting the claim set is outside the scope of this library.

```rust
  let sd_jwt: SdJwt = SdJwt::parse(sd_jwt_string)?;
  let claims_set: // extract claims from `sd_jwt.jwt`.
  let decoder = SdObjectDecoder::new();
  let decoded_object = decoder.decode(claims_set, &sd_jwt.disclosures)?;
```
`decoded_object`:

```json
{
  "given_name": "John",
  "family_name": "Doe",
  "phone": [
    "+49 123456",
    "+49 234567"
  ],
  "address": {
    "region": "Anystate",
    "street_address": "123 Main St"
  }
}

```

Note:
* `street_address` and `address` are recursively decoded.
* `_sd_alg` property was removed.


<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#top">back to top</a>)</p>

<!-- LICENSE -->
## License

Distributed under the Apache License. See `LICENSE` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/iotaledger/template.svg?style=for-the-badge
[contributors-url]: https://github.com/iotaledger/template/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/iotaledger/template.svg?style=for-the-badge
[forks-url]: https://github.com/iotaledger/template/network/members
[stars-shield]: https://img.shields.io/github/stars/iotaledger/template.svg?style=for-the-badge
[stars-url]: https://github.com/iotaledger/template/stargazers
[issues-shield]: https://img.shields.io/github/issues/iotaledger/template.svg?style=for-the-badge
[issues-url]: https://github.com/iotaledger/template/issues
[license-shield]: https://img.shields.io/github/license/iotaledger/template.svg?style=for-the-badge
[license-url]: https://github.com/iotaledger/sd-jwt/blob/main/LICENSE
[discord-shield]: https://img.shields.io/badge/Discord-9cf.svg?style=for-the-badge&logo=discord
[discord-url]: https://discord.iota.org
[stackexchange-shield]: https://img.shields.io/badge/StackExchange-9cf.svg?style=for-the-badge&logo=stackexchange
[stackexchange-url]: https://iota.stackexchange.com
