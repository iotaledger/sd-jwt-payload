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

Rust implementation of the [Selective Disclosure for JWTs (SD-JWT) **version 12**](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-12.html)

## Overview

This library supports 
* **Issuing SD-JWTs**:
  - Create a selectively disclosable JWT by choosing which properties can be concealed from a verifier.
    Concealable claims are replaced with their disclosure's digest.
  - Adding decoys to both JSON objects and arrays.
  - Requiring an holder's key-bind.
* **Managing SD-JWTs**  
  - Conceal with ease any concealable property.
  - Insert a key-bind.
* **Verifying SD-JWTs**
  - Recursively replace digests in objects and arrays with their corresponding disclosure value.

`Sha-256` hash function is shipped by default, encoding/decoding with other hash functions is possible. 

## Getting started
Include the library in your `cargo.toml`.

```bash
[dependencies]
sd-jwt-payload = { version = "0.4.0" }
```

## Examples

See [sd_jwt.rs](./examples/sd_jwt.rs) for a runnable example.

## Usage

This library consists of the major structs:
1. [`SdJwtBuilder`](./src/builder.rs): creates SD-JWTs.
2. [`SdJwt`](./src/sd_jwt.rs): handles SD-JWTs.
3. [`Disclosure`](./src/disclosure.rs): used throughout the library to represent disclosure objects.
4. [`Hasher`](./src/hasher.rs): a trait to provide hash functions create and replace disclosures.
5. [`Sha256Hasher`](./src/hasher.rs): implements `Hasher` for the `Sha-256` hash function.
6. [`JwsSigner`](./src/signer.rs): a trait used to create JWS signatures.


### Creation
Any JSON object can be used to create an SD-JWT:

```rust
  let object = json!({
    "sub": "user_42",
    "given_name": "John",
    "family_name": "Doe",
    "email": "johndoe@example.com",
    "phone_number": "+1-202-555-0101",
    "phone_number_verified": true,
    "address": {
      "street_address": "123 Main St",
      "locality": "Anytown",
      "region": "Anystate",
      "country": "US"
    },
    "birthdate": "1940-01-01",
    "updated_at": 1570000000,
    "nationalities": [
      "US",
      "DE"
    ]
  });
```


```rust
  let builder: SdJwtBuilder = SdJwtBuilder::new(object);
```
This creates a stateful builder with `Sha-256` hash function by default to create disclosure digests. 

*Note: `SdJwtBuilder` is generic over `Hasher` which allows custom encoding with other hash functions.*

The builder can encode any of the object's values or array elements, using the `make_concealable` method. Suppose the value of `street_address` in 'address' should be selectively disclosed as well as the entire value of `address` and the first `phone` value.


```rust
  builder
    .make_concealable("/email")?
    .make_concealable("/phone_number")?
    .make_concealable("/address/street_address")?
    .make_concealable("/address")?
    .make_concealable("/nationalities/0")?
```

*Note: the `make_concealable` method takes a [JSON Pointer](https://datatracker.ietf.org/doc/html/rfc6901) to determine the element to conceal inside the JSON object.*


The builder also supports adding decoys. For instance, the amount of phone numbers and the amount of claims need to be hidden.

```rust
  builder
    .add_decoys("/nationalities", 1)? // Adds 1 decoys to the array `nationalities`.
    .add_decoys("", 2)? // Adds 2 decoys to the top level object.
```

Through the builder an issuer can require a specific key-binding that will be verified upon validation:

```rust
  builder
    .require_key_binding(RequiredKeyBinding::Kid("key1".to_string()))
```

Internally, builder's object now looks like:

```json
{
  "_sd": [
    "5P7JOl7w5kWrMDQ71U4ts1CHaPPNTKDqOt9OaOdGMOg",
    "73rQnMSG1np-GjzaM-yHfcZAIqmeaIK9Dn9N0atxHms",
    "s0UiQ41MTAPnjfKk4HEYet0ksuMo0VTArCwG5ALiC84",
    "v-xRCoLxbDcL5NZGX9uRFI0hgH9gx3uX1Y1EMcWeC5k",
    "z7SAFTHCOGF8vXbHyIPXH6TQvo750AdGXhvqgMTA8Mw"
  ],
  "_sd_alg": "sha-256",
  "cnf": {
    "kid": "key1"
  },
  "sub": "user_42",
  "given_name": "John",
  "family_name": "Doe",
  "nationalities": [
    {
      "...": "xYpMTpfay0Rb77IWvbJU1C4JT3kvJUftZHxZuwfiS1M"
    },
    "DE",
    {
      "...": "GqcdlPi6GUDcj9VVpm8kj29jfXCdyBx2GfWP34339hI"
    }
  ],
  "phone_number_verified": true,
  "updated_at": 1570000000,
  "birthdate": "1940-01-01"
}
```

*Note: no JWT claims like `exp` or `iat` are added. If necessary, these need to be added and validated manually.*

To create the actual SD-JWT the `finish` method must be called on the builder:

```rust
  let signer = MyHS256Signer::new(); 
  let sd_jwt = builder
    // ...
    .finish(&signer, "ES256")
    .await?;
```

```
eyJ0eXAiOiJTRC1KV1QiLCJhbGciOiJIUzI1NiJ9.eyJnaXZlbl9uYW1lIjoiSm9obiIsImZhbWlseV9uYW1lIjoiRG9lIiwicGhvbmUiOlt7Ii4uLiI6ImVaVm4wS2tRbV9UOHgteDU3VnhZdC1fTW1ORzkxU2gzNEUtYlpFbk5mV1kifSwiKzQ5IDIzNDU2NyIseyIuLi4iOiJLQWlKSXgwdGt0UVJYQnhaU0JWVmxkOTI5OGJaSXAyV2twa0RZRGEzQ1dRIn0seyIuLi4iOiJDQktBUlBoNnNkVENKeWxpWjdwQk9Zeml4N1o0QmI0eVJoMEV5a0hYMlV3In0seyIuLi4iOiJvaTFLZ3NZWGdxQkZYVVh2YlZhSFNHWVlhV2hrQjVSTDU1VDkwR2xfNXMwIn1dLCJfc2QiOlsiSmo1akJlR0Vhd1k2dlJ2bUhEZzU1RWplQUlQOEZWaFdFVjJGY3poVVhyWSIsIjhlcXBoQlBKeUNCZ1VKaE5XTlA3Y2ktWTc5TjYxNXdwWlFyeGk1RDRqdTgiLCJfaE9VNXB1SmpOelNCaEswYndoM2g4X2I2SDZuTjd2ZF83STB1VHA4ME1vIiwiR190SDcwTXJmQ2tWTTBIaHNIOVJFT2JJdDFFaTE5NDc3eTZDRXNTMFpsbyIsInpQNTZNZUgwcnlqenFoOUthZHJiNUM5WjJCRTJGV2c4bmIzZzByUjNMU0EiLCJkZ2ZWVzExaXA5T095Vmk4TTRoMVJqWEs4YWt3N0lDZU1Ra2pVd1NJNmlVIiwiQngzM21PeVRGNS13OGdSUzV5TDRZUTRkaWc0NFYzbG1IeGsxV1Jzc183VSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.knTqw4FMCplHoMu7mfiix7dv4lIjYgRIn-tmuemAhbY~WyJHaGpUZVYwV2xlUHE1bUNrVUtPVTkzcXV4WURjTzIiLCAic3RyZWV0X2FkZHJlc3MiLCAiMTIzIE1haW4gU3QiXQ~WyJVVXVBelg5RDdFV1g0c0FRVVM5aURLYVp3cU13blUiLCAiYWRkcmVzcyIsIHsicmVnaW9uIjoiQW55c3RhdGUiLCJfc2QiOlsiaHdiX2d0eG01SnhVbzJmTTQySzc3Q194QTUxcmkwTXF0TVVLZmI0ZVByMCJdfV0~WyJHRDYzSTYwUFJjb3dvdXJUUmg4OG5aM1JNbW14YVMiLCAiKzQ5IDEyMzQ1NiJd~
```

### Handling

Once an SD-JWT is obtained, any concealable property can be omitted from it by creating a presentation and calling the
`conceal` method:

```rust
  let mut sd_jwt = SdJwt::parse("...")?;
  let hasher = Sha256Hasher::new();
  let (presented_sd_jwt, removed_disclosures) = sd_jwt
    .into_presentation(&hasher)?
    .conceal("/email")?
    .conceal("/nationalities/0")?
    .finish()?;
```

To attach a key-binding JWT (KB-JWT) the `KeyBindingJwtBuilder` struct can be used:

```rust
  let mut sd_jwt = SdJwt::parse("...")?;
  // Can be used to check which key is required - if any.
  let requird_kb: Option<&RequiredKeyBinding> = sd_jwt.required_key_binding();

  let signer = MyJwkSigner::new();
  let hasher = Sha256Hasher::new();
  let kb_jwt = KeyBindingJwtBuilder::new()
    .nonce("abcd-efgh-ijkl-mnop")
    .iat(time::now())
    .finish(&sd_jwt, &hasher, "ES256", &signer)
    .await?;
  
  let (sd_jwt, _) = sd_jwt.into_presentation(&hasher)?
    .attach_key_binding_jwt(kb_jwt)
    .finish()?;
```

### Verifying

The SD-JWT can be turned into a JSON object of its disclosed values by calling the `into_disclosed_object` method:

```rust
  let mut sd_jwt = SdJwt::parse("...")?;
  let disclosed_object = sd_jwt.into_disclosed_object(&hasher)?;
```
`disclosed_object`:

```json
{
  "address": {
    "country": "US",
    "locality": "Anytown",
    "region": "Anystate",
    "street_address": "123 Main St"
  },
  "phone_number": "+1-202-555-0101",
  "cnf": {
    "kid": "key1"
  },
  "sub": "user_42",
  "given_name": "John",
  "family_name": "Doe",
  "nationalities": [
    "DE"
  ],
  "phone_number_verified": true,
  "updated_at": 1570000000,
  "birthdate": "1940-01-01"
}

```

Note:
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
