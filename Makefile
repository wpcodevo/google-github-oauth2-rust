start-server:
	cargo watch -q -c -w src/ -x run

install:
	cargo add actix-web
	cargo add actix-cors
	cargo add serde --features derive
	cargo add serde_json
	cargo add chrono --features serde
	cargo add env_logger
	cargo add jsonwebtoken
	cargo add dotenv
	cargo add uuid --features v4
	cargo add reqwest --features json
	# HotReload
	cargo install cargo-watch 