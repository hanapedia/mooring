{
  description = "mooring — Kubernetes-native egress NAT";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forEachSystem = nixpkgs.lib.genAttrs systems;
    in {
      devShells = forEachSystem (system:
        let pkgs = nixpkgs.legacyPackages.${system};
        in {
          default = pkgs.mkShell {
            LIBBPF_BPF_DIR = "${pkgs.libbpf}/include/bpf";

            nativeBuildInputs = with pkgs; [
              # BPF toolchain
              llvmPackages.clang-unwrapped
              llvmPackages.llvm
              bpftools
              libbpf
              pkg-config

              # Go
              go
              gofumpt
              golangci-lint

              # Task runner
              go-task

              # Kubernetes
              kubernetes-helm
              kind
              krew
              kustomize
              kubectl
              cilium-cli
              hubble

              # Testing
              setup-envtest

              # Utilities
              yq-go
              jq
              pinact
              containerlab
            ];
          };
        }
      );
    };
}
