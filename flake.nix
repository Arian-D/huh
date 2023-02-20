{
  description = "huh";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    rust-overlay.url = "github:oxalica/rust-overlay";
    cargo2nix.url = "github:cargo2nix/cargo2nix/release-0.11.0";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = inputs:
    with inputs;
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ cargo2nix.overlays.default ];
        };
        rustPkgs = pkgs.rustBuilder.makePackageSet {
          rustVersion = "latest";
          rustChannel = "nightly";
          packageFun = import ./Cargo.nix;
        };
        pkgName = "huh";
      in with pkgs; rec {
        packages = {
          ip-logger = (rustPkgs.workspace.ip-logger { }).bin;
          default = packages.ip-logger;

          docker-image = pkgs.dockerTools.buildImage {
            name = "${pkgName}";
            config.Cmd = [
              "${packages.default}/bin/${pkgName}"
            ];
          };

        };
        devShells.default = mkShell {
          nativeBuildInputs = [
            cargo2nix.packages.${system}.cargo2nix
            openssl
            sqlite
            pkg-config
            cargo-watch
            rust-analyzer
          ];
        };
      });
}
