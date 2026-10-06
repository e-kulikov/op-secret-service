# Changelog

## 0.1.0 (2026-10-06)


### Features

* **attrs:** add attribute identity and the allow list ([b847a0c](https://github.com/e-kulikov/op-secret-service/commit/b847a0c08aaa1f0388fdcb61da4657869c98d50e))
* **cli:** add doctor and config init ([a6dccf4](https://github.com/e-kulikov/op-secret-service/commit/a6dccf45a1759ee5494448bdadd2c39909729947))
* **config:** keep the daemon alive for an hour by default ([fe1a54c](https://github.com/e-kulikov/op-secret-service/commit/fe1a54c2aa13af10bf2d049276fddcce259cae6b))
* **config:** load configuration from TOML and the environment ([72f4a49](https://github.com/e-kulikov/op-secret-service/commit/72f4a492cf3db1dee74af91d09558bba76d15604))
* **crypto:** add Secret Service session encryption ([0c9f82c](https://github.com/e-kulikov/op-secret-service/commit/0c9f82c01989cf613cfe8841ae983d1bf6fdaeca))
* **dbus:** serve the Secret Service API on the session bus ([68f6f06](https://github.com/e-kulikov/op-secret-service/commit/68f6f0639782443dc5630988b53e0b2eeb2a6f77))
* **doctor:** warn about plaintext gh and glab tokens ([63771be](https://github.com/e-kulikov/op-secret-service/commit/63771be37e2dd7b744b367c1111e200a773df0ec))
* initial implementation of op-secretd ([e859eae](https://github.com/e-kulikov/op-secret-service/commit/e859eae7b39a8886073fea3f7f69de40fe516e59))
* **op:** run the 1Password CLI natively, through WSL, or with a service account ([982c58c](https://github.com/e-kulikov/op-secret-service/commit/982c58ce36b824f967af3e53d170dcd2de8bfd24))
* **store:** keep secrets as 1Password items with an in-memory index ([89142a6](https://github.com/e-kulikov/op-secret-service/commit/89142a6640de2bf9cd1d56d8d2e628a678da9483))


### Bug Fixes

* **cli:** report a taken bus name and bus failures with their own error kinds ([ae2a440](https://github.com/e-kulikov/op-secret-service/commit/ae2a440c844dfb1dd2a567f4fc4f8aedcd076387))
* **op:** retry transient client errors and cap parallel reads at four ([4cbae7e](https://github.com/e-kulikov/op-secret-service/commit/4cbae7e44fa7ed5e5b638c7ffd8c0dead6b06258))


### Performance Improvements

* **lifecycle:** stop scanning the vault when the daemon starts ([1b2e1c8](https://github.com/e-kulikov/op-secret-service/commit/1b2e1c854f517609f10caa47122185f79abab435))
* **store:** read single items directly and load the index in parallel ([ed88d64](https://github.com/e-kulikov/op-secret-service/commit/ed88d64de971577fd9e682790bb1df28b0558edf))
* **store:** search by a subset of attributes with one listing, using attribute tags ([9b1b6e0](https://github.com/e-kulikov/op-secret-service/commit/9b1b6e02116d283f35dc799410ce51015886cc5f))
