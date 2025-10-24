{ pkgs ? import <nixpkgs> {} }:

let
  pkgsCross = pkgs.pkgsCross.musl64;
in
  pkgsCross.rustPlatform.buildRustPackage {
    pname = "pacemaker_helper";
    version = "1.0.0";
    src = ./.;
    
    cargoLock = {
      lockFile = ./Cargo.lock;
    };
    
    # Ensure static linking
    CARGO_BUILD_RUSTFLAGS = [
      "-C" "target-feature=+crt-static"
    ];
  }
