{
  description = "library implementing ACME server functionality";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs = { self, ... }@inputs:
  inputs.flake-parts.lib.mkFlake { inherit inputs self; } {
    flake = {

    };
    systems = [
      "x86_64-linux"
      "aarch64-linux"
    ];
    perSystem = { self', pkgs, ... }: {
      devShells = {
        default = pkgs.mkShell {
          nativeBuildInputs = [
            pkgs.python3
          ];
        };
      };

      packages = {
        default = self'.packages.acme2certifier;
        acme2certifier = pkgs.callPackage ./utils/flake/acme2certifier.nix {
          ca_handler = "acme_ca_handler.py"; # Override this to pick CA handler
          config = {};
          inherit self pkgs;
        };
      };

      apps = {

      };
    };
  };
}
