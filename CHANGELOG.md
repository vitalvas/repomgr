# Changelog

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
