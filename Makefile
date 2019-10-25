all: clean build

.PHONY: build
build: build_ah build_galaxy

.PHONY: build_ah
build_ah:
	cd ah && $(MAKE) build 

.PHONY: build_galaxy
build_galaxy:
	@echo 'build Galaxy (public) collection'
	ansible-galaxy collection build

.PHONY: clean
clean:
	@echo "removing old artifacts and intermediate files"
	cd ah && $(MAKE) clean
	rm -f ansible-amazon-*.tar.gz
