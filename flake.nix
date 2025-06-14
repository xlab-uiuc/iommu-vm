{
  description = "A flake for the REX project";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs, ... }:
    let
      system = "x86_64-linux";

      basePkgs = import nixpkgs {
        inherit system;
      };

      remoteNixpkgsPatches = [
        {
          meta.description = "cc-wrapper: remove -nostdlibinc";
          url = "https://github.com/chinrw/nixpkgs/commit/0016d524d02035187216a6df9fff1dbffadfa81b.patch";
          sha256 = "sha256-kYTSw+8vByZcCHXfVeWqi0/XVNjo8YJSey03k/+uxvw=";
        }
        {
          meta.description = "cc-wrapper: disable warn about cross-compile";
          url = "https://github.com/chinrw/nixpkgs/commit/3a6374fce7c048a86e7ff56671b1dbc4974757a9.patch";
          sha256 = "sha256-pxgls4+wn5wekkQH8etdoYV3mAY8omviZ/MOu9sekE8";
        }
      ];

      patchedNixpkgsSrc = basePkgs.applyPatches {
        name = "nixpkgs-patched";
        src = basePkgs.path;
        patches = map basePkgs.fetchpatch remoteNixpkgsPatches;
      };

      patchedBindgen =
        (self: super: {
          rust-bindgen-unwrapped = super.rust-bindgen-unwrapped.overrideAttrs (finalAttrs: oldAttrs: {
            src = super.fetchFromGitHub {
              owner = "rust-lang";
              repo = "rust-bindgen";
              rev = "20aa65a0b9edfd5f8ab3e038197da5cb2c52ff18";
              sha256 = "sha256-OrwPpXXfbkeS7SAmZDZDUXZV4BfSF3e/58LJjedY1vA=";
            };
            cargoDeps = pkgs.rustPlatform.fetchCargoVendor {
              inherit (finalAttrs) pname src version;
              hash = finalAttrs.cargoHash;
            };
            cargoHash = "sha256-e94pwjeGOv/We6uryQedj7L41dhCUc2wzi/lmKYnEMA=";
          });
        });

      patchedPkgs = import patchedNixpkgsSrc {
        inherit system;
        overlays = [ patchedBindgen ];
      };

      pkgs = import nixpkgs {
        inherit system;
        # overlays = [ overrideLLVM ];
      };

      wrapCC = cc: pkgs.wrapCCWith {
        inherit cc;
        extraBuildCommands = ''
          # Remove the line that contains "-nostdlibinc"
          sed -i 's|-nostdlibinc||g' "$out/nix-support/cc-cflags"
          echo " -resource-dir=${pkgs.llvmPackages.clang}/resource-root" >> "$out/nix-support/cc-cflags"
          echo > "$out/nix-support/add-local-cc-cflags-before.sh"
        '';
      };



      # wrappedClang = wrapCC pkgs.llvmPackages.clang.cc;
      # lib = nixpkgs.lib;

      # Use unwrapped clang & lld to avoid warnings about multi-target usage
      rexPackages = with pkgs; [
        # Kernel builds
        autoconf
        bc
        binutils
        bison
        cmake
        diffutils
        elfutils
        elfutils.dev
        fakeroot
        findutils
        flex
        gcc
        glibc.dev
        getopt
        gnumake
        ncurses
        openssl.dev
        pahole
        pkg-config
        xz.dev
        zlib
        zlib.dev

        ninja
        patchedPkgs.rust-bindgen
        pahole
        strace
        zstd
        eza
        perf-tools
        # linuxKernel.packages.linux_latest.perf

        # Clang kernel builds
        patchedPkgs.llvmPackages.clang
        # wrappedClang
        # llvmPackages.libcxxStdenv
        lld
        mold
        # llvmPackages.bintools

        qemu
        busybox
        perf-tools

        # for llvm/Demangle/Demangle.h
        # libllvm
        # libllvm.dev
        # libgcc
        # libclang.lib
        # libclang.dev

        # meson deps
        meson
        curl
        perl

        bear # generate compile commands
        rsync # for make headers_install
        gdb

        # bmc deps
        iproute2
        memcached
        python3

        vim
        nano


        python3Packages.pip
        python3Packages.virtualenv
        python3Packages.numpy
        python3Packages.pandas
        python3Packages.matplotlib
        python3Packages.sphinx
        python3Packages.sphinx_rtd_theme
        python3Packages.docutils
        python3Packages.babel
        python3Packages.pygments
        python3Packages.packaging
        python3Packages.jinja2
        python3Packages.pyelftools
        python3Packages.setuptools
        python3Packages.wheel

        python3Packages.pyyaml  # For config parsing
        python3Packages.requests  # Some scripts might fetch data
        python3Packages.tomli  # For Python 3.11+ support
        python3Packages.pycparser  # For certain C header parsing tasks
        python3Packages.pyparsing  # Used in Meson scripts
        python3Packages.markupsafe
        python3Packages.snowballstemmer

        zoxide # in case host is using zoxide
        openssh # q-script ssh support

        glib
        glib.dev

        git

        libvirt
        # libvirt.dev  # Development headers (if needed)
        libvirt-glib  # If using libvirt with GLib-based apps
        virt-manager  # GUI for managing VMs (optional)

        snappy
        numactl 
        rdma-core 
        libaio 
        bzip2
        # sudo
      ];

      # (pkgs.buildFHSEnv.override { stdenv = pkgs.llvmPackages.stdenv; })
      fhs = (pkgs.buildFHSEnv.override { stdenv = pkgs.llvmPackages.stdenv; })
        {
          name = "qemu-viommu-env";
          targetPkgs = pkgs: rexPackages;
          runScript = "bash";

          profile = ''
            export LD_LIBRARY_PATH=${pkgs.libgcc.lib}/lib:$LD_LIBRARY_PATH
            export NIX_ENFORCE_NO_NATIVE=0
          '';
        };
    in
    {
      devShells."${system}" = {
        default = fhs.env;

        rex = pkgs.mkShell {
          packages = rexPackages;
          # Disable default hardening flags. These are very confusing when doing
          # development and they break builds of packages/systems that don't
          # expect these flags to be on. Automatically enables stuff like
          # FORTIFY_SOURCE, -Werror=format-security, -fPIE, etc. See:
          # - https://nixos.org/manual/nixpkgs/stable/#sec-hardening-in-nixpkgs
          # - https://nixos.wiki/wiki/C#Hardening_flags
          hardeningDisable = [ "all" ];

          shellHook = ''
            export LD_LIBRARY_PATH=${pkgs.libgcc.lib}/lib:$LD_LIBRARY_PATH
            echo "loading rex env"
            export NIX_ENFORCE_NO_NATIVE=0
          '';
        };
      };
    };

}

