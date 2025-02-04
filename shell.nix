{ 
  pkgs ? import <nixpkgs> {},
  system ? builtins.currentSystem,
  lib ? pkgs.lib,
  ...
}:

pkgs.mkShell {
  name = "nmap-terminal-visualizer-devshell";
  
  buildInputs = with pkgs; [
    go
    gopls
    go-tools
    golangci-lint
    delve
    nmap
    wireshark
    tcpdump
    netcat
    git
    gnumake
    curl
    jq
    yq
    graphviz
    imagemagick
  ];

  shellHook = ''
    echo "🔍 NMAP Terminal Visualizer Development Environment"
    echo "-------------------------------------------"
    echo "Go Version: $(go version)"
    echo "Nmap Version: $(nmap --version | head -n 1)"
    
    export NMAP_VISUALIZER_DEV=1
    export GOPATH="$(pwd)/.go"
    export GOCACHE="$(pwd)/.cache/go-build"
    
    mkdir -p $GOPATH
    mkdir -p $GOCACHE

    alias build='go build -v ./...'
    alias test='go test -v ./...'
    alias lint='golangci-lint run'
    alias scan='nmap -sV localhost'

    go mod download
  '';
}
