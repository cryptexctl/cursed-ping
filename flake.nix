{
  description = "cursed ping";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    ...
  }:
    {
		overlays.default = final: prev: {
			inherit (self.packages.${prev.system}) bpf2go;
		};
    } // flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [ self.overlays.default ];
      };
    in {
      packages = {
      	bpf2go = pkgs.buildGoModule rec {
			pname = "bpf2go";
			version = "0.17.2";
			src = pkgs.fetchFromGitHub {
              owner = "cilium";
              repo = "ebpf";
              rev = "v${version}";
              hash = "sha256-lIJsITwdt6PuTMEHXJekBKM2rgCdPJF+i+QHt0jBgp8=";
            };
            vendorHash = "sha256-Ygljpp5GVM2EbD51q1ufqA6z5yJnrXVEfVLIPrxfm18=";
            subPackages = [ "cmd/bpf2go" ];
            doCheck = false;
		};
        pinger = pkgs.buildGoModule rec {
          pname = "cursed-ping";
          version = "1";
          src = ./.;
          vendorHash = "sha256-RxmMgiMATpO31VP85dlkOXl/nLbVD5W1dfWHhuGKcME=";
          deleteVendor = true;

          ldflags = ["-s -w"];
          env.CGO_ENABLED = 0;
          nativeBuildInputs = with pkgs; [clang bpftools libllvm linuxHeaders bpf2go glibc_multi libbpf];
          hardeningDisable = [ "all" ];
          buildInputs = nativeBuildInputs;

          postConfigure = ''
            go generate ./...
          '';

          meta = with pkgs.lib; {
            description = "cursed ping";
            license = licenses.wtfpl;
          };
        };
      };
      formatter = pkgs.alejandra;
    });
}
