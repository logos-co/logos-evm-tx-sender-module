{
  description = "Logos tx_sender_module — the one EVM transaction sender: nonce ledger, one-approval call bundles, ordered broadcast, write-ahead history.";

  inputs = {
    logos-module-builder.url = "github:logos-co/logos-module-builder";
    # The follows is for LOCK SIZE: without it each dependency drags its own module-builder
    # subtree. It is not a compatibility measure — a dependency's published `.lidl` and the
    # client generated from it are byte-identical either way.
    eth_rpc_module = {
      url = "github:logos-co/logos-evm-eth-rpc-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    fee_module = {
      url = "github:logos-co/logos-evm-fee-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
    keystore_module = {
      url = "github:logos-co/logos-evm-keystore-module";
      inputs.logos-module-builder.follows = "logos-module-builder";
    };
  };

  outputs = inputs@{ self, logos-module-builder, ... }:
    let
      nixpkgs = logos-module-builder.inputs.nixpkgs;
      systems = [ "aarch64-darwin" "x86_64-darwin" "aarch64-linux" "x86_64-linux" ];

      # x86_64-windows is a cross PSEUDO-SYSTEM the builder already understands
      # (logos-module-builder lib/common.nix routes it to logos-nix.lib.mkWindowsPkgs,
      # and picks the build platform separately). It is a target, never a host we
      # evaluate nixpkgs natively for, so it only ever belongs in `packages`.
      targets = systems ++ [ "x86_64-windows" ];
      forAllTargets = f: nixpkgs.lib.genAttrs targets f;
    in
    {
      packages = forAllTargets (system:
        (logos-module-builder.lib.mkLogosModule {
          src = ./.;
          configFile = ./metadata.json;
          flakeInputs = inputs;
        }).packages.${system});
    };
}
