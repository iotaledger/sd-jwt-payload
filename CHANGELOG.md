# Change Log

## [0.5.0]
Implement latest SD-JWT specification: [RFC9901](https://www.rfc-editor.org/rfc/rfc9901.html).

## [0.4.0]

### Added
- `SdJwtPresentationBuilder::conceal_all` removes all concealable claims.
- `SdJwtPresentationBuilder::disclose` undos the concealament of a previously concealed
  claim.


## [0.3.0]

### Added
- `JwsSigner` trait defining an interface for types that can produce JWS.
- `KeyBindingJwt` type for handling KB-JWTs.
- `KeyBindingJwtBuilder` type for creating KB-JWTs.
- `SdJwtPresentationBuilder` for removing disclosable claims or adding a KB-JWT.

### Changed
- Replaced `SdObjectEncoder` with `SdJwtBuilder` that - through `JwsSigner` - allows
  for the creation of a whole `SD-JWT` token, instead of just disclosures and a JWT
  payload.

## [0.2.1]

### Added
- Added `FromStr` implementation for `SdJwt`.

### Removed
- Removed `Serialize` and `Deserialize` implementation for `SdJwt`.

## [0.2.0]

### Added
- `HEADER_TYP` constant.

### Changed
- Changed `SdObjectEncoder::conceal` to take a JSON pointer string, instead of a string array.

### Removed
- Removed `SdObjectEncoder::conceal_array_entry` (replaced by `SdObjectEncoder::conceal`).

### Fixed
- Decoding bug when objects inside arrays include digests and plain text values.

## [0.1.2]
- 07 Draft implementation.
