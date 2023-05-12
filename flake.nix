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
    (flake-utils.lib.eachDefaultSystem (
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
            zig build -Dcpu=baseline --prefix $out install
            runHook postInstall
          '';
        };

        devShell = pkgs.mkShell {
          nativeBuildInputs = [
            zig.packages.${system}.master
          ];
        };
      }
    ))
    // {
      nixosModules.ensky = {
        config,
        pkgs,
        lib,
        ...
      }:
        with lib; let
          cfg = config.services.ensky;
          settingsFormat = pkgs.formats.json {};
          configFile = settingsFormat.generate "ensky-config.json" cfg.settings;
        in {
          options.services.ensky = {
            enable = mkEnableOption "ensky";
            package = mkOption {
              type = types.package;
              default = pkgs.ensky;
              description = "the ensky package to use";
            };

            settings = mkOption {
              type = types.submodule {
                freeformType = settingsFormat.type;
                options = {
                  interface = mkOption {
                    type = types.str;
                    default = "wg0";
                    description = "the interface to bind to";
                  };

                  gossip_address = mkOption {
                    type = types.str;
                    default = "0.0.0.0";
                    description = "the address to bind to for gossip";
                  };

                  gossip_port = mkOption {
                    type = types.int;
                    default = 5554;
                    description = "the port to bind to for gossip";
                  };

                  gossip_secret_path = mkOption {
                    type = types.path;
                    description = "the path to the gossip secret";
                  };

                  peers = mkOption {
                    type = types.listOf (types.submodule {
                      options = {
                        pubkey = mkOption {
                          type = types.str;
                          description = "the public key of the peer";
                        };

                        endpoints = mkOption {
                          type = types.listOf types.str;
                          default = [];
                          description = "the endpoint of the peer";
                        };

                        allowed_ips = mkOption {
                          type = types.listOf types.str;
                          description = "the allowed ips of the peer";
                        };
                      };
                    });
                    default = [];
                    description = "the peers to manage";
                  };
                };
              };
              default = {};
              description = "the settings for ensky";
            };
          };

          config = mkIf cfg.enable {
            systemd.services.ensky = {
              description = "a flexible wireguard mesher";

              path = [pkgs.wireguard-tools];

              serviceConfig = {
                Type = "simple";
                ExecStart = "${cfg.package}/bin/ensky ${configFile}";
                Restart = "always";
                RestartSec = "10";

                DynamicUser = true;
                AmbientCapabilities = "CAP_NET_ADMIN";
                CapabilityBoundingSet = "CAP_NET_ADMIN";
              };

              after = ["network.target"];
              wantedBy = ["multi-user.target"];
            };
          };
        };
    };
}
