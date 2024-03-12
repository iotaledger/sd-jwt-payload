# Change Log

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
