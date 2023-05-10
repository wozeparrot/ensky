{
  description = "ensky: a flexible wireguard mesher";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  inputs.flake-utils.url = "github:numtide/flake-utils";
  inputs.zig.url = "github:mitchellh/zig-overlay";

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    zig,
  }:
    flake-utils.lib.eachDefaultSystem (
      system: let
        pkgs = import nixpkgs {
          inherit system;
        };
      in {
        packages.ensky = pkgs.stdenv.mkDerivation {
          pname = "ensky";
          version = "0.1.0";

          src = ./.;

          nativeBuildInputs = [
            zig.packages.${system}.master
          ];

          dontConfigure = true;

          preBuild = ''
            export HOME=$TMPDIR
          '';

          installPhase = ''
            runHook preInstall
            zig build -Doptimize=ReleaseSafe -Dcpu=baseline --prefix $out install
            runHook postInstall
          '';
        };

        devShell = pkgs.mkShell {
          nativeBuildInputs = [
            zig.packages.${system}.master
          ];
        };
      }
    );
}
