# Changelog

## [0.7.0](https://github.com/vitalvas/repomgr/compare/v0.6.0...v0.7.0) (2026-11-25)


### Features

* add rpm repository management with init, add, and build ([b4caa74](https://github.com/vitalvas/repomgr/commit/b4caa74e5b7ab8559307e3ffadcad5281a746321))
* split readme into deb and rpm docs and drop design specs ([b72dc39](https://github.com/vitalvas/repomgr/commit/b72dc39f008d02c074a2f28933f022be40934410))


### Bug Fixes

* validate RPM headers and publish repository metadata safely ([7928731](https://github.com/vitalvas/repomgr/commit/792873124ad629f8ab51c286e9de41564596a40d))

## [0.6.0](https://github.com/vitalvas/repomgr/compare/v0.5.0...v0.6.0) (2026-11-23)


### Features

* add deb-mirror command and case-insensitive deb822 fields ([6b26ea5](https://github.com/vitalvas/repomgr/commit/6b26ea54d76da6916e96b5619255c26227c6604c))


### Bug Fixes

* harden deb-mirror index checks and keep source URL paths verbatim ([878b9ca](https://github.com/vitalvas/repomgr/commit/878b9ca22d3c24fd75dfd9b873915db2f8ea71d5))
* harden mirror, deb parser, and upload inbox ([b26f93b](https://github.com/vitalvas/repomgr/commit/b26f93b36a303cefdba9149787910a08884e1543))

## [0.5.0](https://github.com/vitalvas/repomgr/compare/v0.4.0...v0.5.0) (2026-11-22)


### Features

* add architecture directory to pool layout ([afb3108](https://github.com/vitalvas/repomgr/commit/afb310852eab98886d2dfef9180831eff5ad8aee))

## [0.4.0](https://github.com/vitalvas/repomgr/compare/v0.3.3...v0.4.0) (2026-11-22)


### Features

* optional repo.yaml, Release defaults, SHA-256 signatures ([08b75f5](https://github.com/vitalvas/repomgr/commit/08b75f50d82aff72f75086a528c6a83f9a8e0e68))

## [0.3.3](https://github.com/vitalvas/repomgr/compare/v0.3.2...v0.3.3) (2026-11-22)


### Bug Fixes

* add upload releases ([58eaa12](https://github.com/vitalvas/repomgr/commit/58eaa125914da91ee209a689dd9d87850d21ba63))

## [0.3.2](https://github.com/vitalvas/repomgr/compare/v0.3.1...v0.3.2) (2026-11-22)


### Bug Fixes

* keep by-hash file mtimes when indexes are unchanged ([387846b](https://github.com/vitalvas/repomgr/commit/387846bae3abda700dbec821b98ea9bf18d155b3))

## [0.3.1](https://github.com/vitalvas/repomgr/compare/v0.3.0...v0.3.1) (2026-11-22)


### Bug Fixes

* keep signed Release files when a suite has no changes ([2cdb2f6](https://github.com/vitalvas/repomgr/commit/2cdb2f681ff8cabfc7882f2f03fc47f429d1b204))

## [0.3.0](https://github.com/vitalvas/repomgr/compare/v0.2.0...v0.3.0) (2026-11-22)


### Features

* move packages from the upload inbox into the pool on build ([5a06cb4](https://github.com/vitalvas/repomgr/commit/5a06cb4d44dd0b659d8415f9d54299dbdf027f60))

## [0.2.0](https://github.com/vitalvas/repomgr/compare/v0.1.0...v0.2.0) (2026-11-22)


### Features

* restore public keys on build, add key.asc, make email optional ([3a34efd](https://github.com/vitalvas/repomgr/commit/3a34efd6f1eb61030e92324fec566396ab21836d))

## [0.1.0](https://github.com/vitalvas/repomgr/compare/v0.0.1...v0.1.0) (2026-11-22)


### Features

* add signed deb repository manager with by-hash indexes ([dd1c511](https://github.com/vitalvas/repomgr/commit/dd1c5111182c5415c13cfad79bcdc3374c52a32e))


### Bug Fixes

* harden deb parsing, pool conflict checks, and cache validation ([8056b29](https://github.com/vitalvas/repomgr/commit/8056b29e76c1d0353ba9469d714b0b8c941b3a86))
