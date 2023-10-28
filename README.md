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

Rust implementation of the [Selective Disclosure for JWTs (SD-JWT) **version 06**](https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-06.html)

## Overview

This library supports 
* **Encoding**:
  - creating disclosers and replacing values in objects and arrays with the digest of their disclosure. 
  - Adding decoys to objects and arrays.
* **Decoding**  
  - Recursively replace digests in objects and arrays with their corresponding disclosure value.

## Getting started
//todo

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
Any JSON object can be encoded, for the following object
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

create an `SdObjectEncoder`

```rust
  let mut encoder = SdObjectEncoder::try_from(object).unwrap();
```
This creates a stateful encoder with `Sha-256` hash function by default to create disclosure digests. 

*Note: `SdObjectEncoder` is generic over `Hasher` which allows custom encoding with other hash functions.*

The encoder can encode any of the object's value's or any array element, using the `conceal` method. Suppose the value of `region` should be selectively disclosed as well as the value of `address` and the second `phone` value.

```rust
  let disclosure1 = encoder.conceal(&["address", "street_address"], None).unwrap();
  let disclosure2 = encoder.conceal(&["address"], None).unwrap();
  let disclosure3 = encoder.conceal_array_entry(&["phone"], 0, None).unwrap();
```

```
"WyJzR05xSUVNc1R2TEdzMTZHbTFleURvbzJtIiwgInN0cmVldF9hZGRyZXNzIiwgIjEyMyBNYWluIFN0Il0"
"WyJvbUVmQlhuQjRoWUpjYWVKamFIaHI0dDFKIiwgImFkZHJlc3MiLCB7InJlZ2lvbiI6IkFueXN0YXRlIiwiX3NkIjpbIjd4cjBUSElKOGxBN0ZTa2hQWEZYb09LQXA5a3dXR3lSR211R013Rk1PQjAiXX1d"
"WyJQTXJ6ZGV3SmgzY1pOMEhUY0ZQZGNQRjVUIiwgIis0OSAxMjM0NTYiXQ"
```
The encoder also supports adding decoys. Suppose the amount of phone numbers and the amount of claims needs to be hidden.

```rust
  encoder.add_decoys(&["phone"], 3).unwrap();
  encoder.add_decoys(&[], 6).unwrap();
```

Add the hash function claim.
```rust
  encoder.add_sd_alg_property();
```

Now `encoder.object()` will return the encoded object.

```json
{
  "given_name": "John",
  "family_name": "Doe",
  "phone": [
    {
      "...": "zqCKmYhtxOIaq5gLHsTwQ3UQ0z3quxa1KMUN0tHEi3Y"
    },
    "+49 234567",
    {
      "...": "RhQdZloNShJxwz4r35BWYAMNWL5pE7bCkmwEqRxwYE0"
    },
    {
      "...": "vIDM6PQidUgI0hcLUtR6qVCiS3-CaBf89x9N2r2XAu4"
    },
    {
      "...": "LCqYyQD9kV18ndKZzNxMSr0ltDV8m6Nznhtm11IZznE"
    }
  ],
  "_sd": [
    "sLmmzUH4_wvp6pkFxvhAwpEZvWZDYDl_OnPoUcqb330",
    "-8vMUT-_K5UtZACaM-kG3ACrxk6fS3rDrwJ9hpXLWCI",
    "QfSuYv2zx06eVxsL16QIdNnAGV8mn79FrN6PfZxMl3Y",
    "NTO4mVnuLRgAeTMWqdcWri90dEd4Ul38-1dU-bwEtEY",
    "dj1gxBb6Pwga4ggv2aGIrPRLOPl9Kgy6DEP4-mX_mDY",
    "7IbILNpUgcsFfwOcovbwaqwDqdqD13rM0fqjJwOtOTg",
    "U5x5qGVCk4gGVRjfx8Dv1BlXZICIaw9EDXqKu6i_A1U"
  ],
  "_sd_alg": "sha-256"
}
```

*Note: no JWT values like `exp` or `iat` are added. These need to be added and validated manually.*

### Creating/Parsing SD-JWT

Sinec creating JWTs is outside the scope of this library, see the full [sd_jwt.rs example](./examples/sd_jwt.rs) where `josekit` is used to create the JWT and how it's used to create the SD-JWT through [`SdJwt`](./src/sd_jwt.rs).

### Decoding

Decoding the previous object by passing all the returned disclosures `vec![disclosure1, disclosure2, disclosure3]` 

```rust
  let decoder = SdObjectDecoder::new_with_sha256_hasher();
  let decoded = decoder.decode(encoder.object(), &disclosures).unwrap();
```
`decoded`:

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
[license-url]: https://github.com/iotaledger/template/blob/main/LICENSE
[discord-shield]: https://img.shields.io/badge/Discord-9cf.svg?style=for-the-badge&logo=discord
[discord-url]: https://discord.iota.org
[stackexchange-shield]: https://img.shields.io/badge/StackExchange-9cf.svg?style=for-the-badge&logo=stackexchange
[stackexchange-url]: https://iota.stackexchange.com
