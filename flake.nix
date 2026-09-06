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
            nativeBuildInputs = with pkgs; [
              # BPF toolchain
              llvmPackages.clang-unwrapped
              bpftools
              libbpf

              # Go
              go

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
