.PHONY: all clean ts-build dev-ts-compile ts-cleanup client-build client-cleanup demon

all: ts-build client-build

ts-build:
	@ echo "[*] building teamserver"
	@ ./teamserver/Install.sh
	@ cd teamserver; GO111MODULE="on" go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go
	@ if command -v sudo >/dev/null 2>&1; then \
		sudo setcap 'cap_net_bind_service=+ep' havoc 2>/dev/null || echo "[!] setcap failed - run as root to bind privileged ports"; \
	fi

dev-ts-compile:
	@ echo "[*] compile teamserver"
	@ cd teamserver; GO111MODULE="on" go build -ldflags="-s -w -X cmd.VersionCommit=$(git rev-parse HEAD)" -o ../havoc main.go

client-build:
	@ echo "[*] building client"
	@ mkdir -p client/Build
	@ cd client/Build && cmake ..
	@ if [ -d "client/Modules" ]; then \
		echo "[*] Modules already installed"; \
	else \
		git clone https://github.com/HavocFramework/Modules client/Modules --single-branch --branch main; \
	fi
	@ cmake --build client/Build -- -j 4

demon:
	@ echo "[*] building demon payload"
	@ cd client/Build && cmake .. && make -j 4

ts-cleanup: 
	@ echo "[*] teamserver cleanup"
	@ rm -rf ./teamserver/bin
	@ rm -rf ./data/loot
	@ rm -rf ./data/x86_64-w64-mingw32-cross 
	@ rm -rf ./data/havoc.db
	@ rm -rf ./data/server.*
	@ rm -rf ./teamserver/.idea
	@ rm -rf ./havoc

client-cleanup:
	@ echo "[*] client cleanup"
	@ rm -rf ./client/Build
	@ rm -rf ./client/Bin/*
	@ rm -rf ./client/Data/database.db
	@ rm -rf ./client/.idea
	@ rm -rf ./client/cmake-build-debug
	@ rm -rf ./client/Havoc
	@ rm -rf ./client/Modules

clean: ts-cleanup client-cleanup
	@ rm -rf ./data/*.db
	@ rm -rf ./data/network_diagrams
	@ rm -f ./auth.db ./auth.db-wal ./auth.db-shm
	@ rm -rf payloads/Demon/.idea
