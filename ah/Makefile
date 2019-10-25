all: clean build

.PHONY: build
build:
	@echo 'build AH (supported) collection'
	mkdir -p plugins/module_utils/aws
	mkdir -p plugins/modules
	for p in `cat core_supported.txt`; do cp -rl ../$$p $$p  ; done
	ansible-galaxy collection build

.PHONY: clean
clean:
	@echo "removing old artifacts and intermediate files"
	rm -rf plugins
	rm -f ansible-amazon-*.tar.gz
