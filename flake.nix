{
  description = "rr debugger with software counters support: https://github.com/sidkshatriya/rr.soft";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-parts.url = "github:hercules-ci/flake-parts";
  };

  outputs =
    inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux"
        "aarch64-linux"
      ];
      perSystem =
        {
          config,
          self',
          inputs',
          pkgs,
          system,
          ...
        }:
        let
          rr_compiled_with =
            flavor: software_counters_plugin:
            pkgs.rr.overrideAttrs (prev: {
              version = "post5.9.0+${flavor}-soft";
              src = ./.;
              nativeBuildInputs = [
                pkgs.pkg-config
                pkgs.ninja
                #pkgs.gdb
                #pkgs.lldb
              ] ++ prev.nativeBuildInputs;
              buildInputs =
                [
                  pkgs.bzip2
                  pkgs.zstd
                  pkgs.lz4
                  pkgs.snappy
                  pkgs.rocksdb
                  pkgs.python3Packages.pexpect
                  pkgs.gdb
                  pkgs.lldb
                  self'.packages.libSoftwareCountersGcc
                  self'.packages.libSoftwareCounters
                ]
                ++ pkgs.lib.optionals (system == "x86_64-linux") [ pkgs.zydis ]
                ++ prev.buildInputs;
              # Removed it from flake, no problems
              preConfigure = "";
              cmakeFlags = prev.cmakeFlags ++ [
                "-DCMAKE_PREFIX_PATH=${pkgs.rocksdb};${pkgs.snappy.dev}"
                "-DSOFTWARE_COUNTERS_PLUGIN=${software_counters_plugin}/lib/libSoftwareCounters.so"
                "-GNinja"
              ];
              dontStrip = true;
            });
          libSoftwareCountersGccFor =
            ver: gccStdenvArg:
            gccStdenvArg.mkDerivation {
              pname = "libSoftwareCountersGcc${ver}";
              version = "0.1";
              src = ./.;
              dontConfigure = true;
              buildInputs = [ pkgs.gmp ];
              buildPhase = ''
                make -C ./compiler-plugins/SoftwareCountersGccPlugin/
              '';
              installPhase = ''
                mkdir -p $out/lib64
                cp compiler-plugins/SoftwareCountersGccPlugin/libSoftwareCountersGcc.so $out/lib64
                # provide an alias to make things easy when building rr.soft
                ln -s $out/lib64/libSoftwareCountersGcc.so $out/lib64/libSoftwareCounters.so
              '';
              meta = {
                homepage = "https://github.com/sidkshatriya/rr.soft";
                description = "libSoftwareCountersGcc";

                license = with pkgs.lib.licenses; [
                  gpl3Plus
                ];
                platforms = [
                  "aarch64-linux"
                  "x86_64-linux"
                ];
              };
            };
          libSoftwareCountersFor =
            ver: clangStdenvArg: llvmPackagesArg:
            clangStdenvArg.mkDerivation {
              pname = "libSoftwareCounters${ver}";
              version = "0.1";
              src = ./.;
              nativeBuildInputs = [
                pkgs.cmake
                pkgs.ninja
                llvmPackagesArg.libllvm
              ];
              cmakeFlags = [
                ''-S=${./.}/compiler-plugins/SoftwareCountersClangPlugin''
                "-GNinja"
              ];
              installPhase = ''
                mkdir -p $out/lib64
                cp libSoftwareCounters.so $out/lib64
              '';
              meta = {
                homepage = "https://github.com/sidkshatriya/rr.soft";
                description = "libSoftwareCounters";

                license = with pkgs.lib.licenses; [
                  asl20
                ];
                platforms = [
                  "aarch64-linux"
                  "x86_64-linux"
                ];
              };
            };
        in
        {
          packages.rr-gcc =
            (rr_compiled_with "gcc" (libSoftwareCountersGccFor "14" pkgs.gcc14Stdenv)).override
              {
                stdenv = pkgs.gcc14Stdenv;
              };
          packages.rr-clang =
            (rr_compiled_with "clang" (libSoftwareCountersFor "19" pkgs.clang19Stdenv pkgs.llvmPackages_19))
            .override
              {
                stdenv = pkgs.clang19Stdenv;
              };
          packages.rr = self'.packages.rr-clang;
          packages.libSoftwareCountersGcc14 = (libSoftwareCountersGccFor "14" pkgs.gcc14Stdenv);
          packages.libSoftwareCountersGcc13 = (libSoftwareCountersGccFor "13" pkgs.gcc13Stdenv);
          packages.libSoftwareCountersGcc = self'.packages.libSoftwareCountersGcc14;
          packages.libSoftwareCounters19 = (
            libSoftwareCountersFor "19" pkgs.clang19Stdenv pkgs.llvmPackages_19
          );
          packages.libSoftwareCounters18 = (
            libSoftwareCountersFor "18" pkgs.clang18Stdenv pkgs.llvmPackages_18
          );
          packages.libSoftwareCounters = self'.packages.libSoftwareCounters19;
          packages.default = self'.packages.rr;
        };
    };
}
