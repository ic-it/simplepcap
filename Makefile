APP_VERSION=0.1.8
APP_PATH=simplepcap
APP_TEST_PATH=tests

# COLORED OUTPUT XD
ccerror	= $(shell tput setaf 1)
ccok	= $(shell tput setaf 2)
ccwarn	= $(shell tput setaf 3)
cctarget= $(shell tput setaf 4)
ccinfo	= $(shell tput setaf 6)
ccreset = $(shell tput sgr0)
INFO	= $(ccinfo)[INFO] |$(ccreset)
WARN	= $(ccwarn)[WARN] |$(ccreset)
ERROR	= $(ccerror)[ERROR]|$(ccreset)
OK		= $(ccok)[OK]   |$(ccreset)


.PHONY: help


# Show this help.
help:
	@awk '/^#/{c=substr($$0,3);next}c&&/^[[:alpha:]][[:alnum:]_-]+:/{print "$(cctarget)" substr($$1,1,index($$1,":")) "$(ccreset)",c}1{c=0}' $(MAKEFILE_LIST) | column -s: -t


# Build the project
install-dev:
	@echo "$(INFO) Installing dev dependencies..."
	@pip install .[dev]


# Run linters
lint:
	@echo "$(INFO) Running linters..."
	@flake8 ./$(APP_PATH)


# Run tests
test:
	@echo "$(INFO) Running tests..."
	@pytest -v ./$(APP_TEST_PATH)


# Build Docs
build-docs:
	@echo "$(INFO) Building docs..."
	@mkdocs build --clean


# Run Docs Server
run-docs:
	@echo "$(INFO) Running docs server..."
	@mkdocs serve


# Update App Version in pyproject.toml, simplepcap/__init__.py
update-version:
	@echo "$(INFO) Updating app version..."
	@sed -i 's/version = "[0-9]\.[0-9]\.[0-9]"/version = "$(APP_VERSION)"/g' pyproject.toml
	@sed -i 's/version-[0-9]\.[0-9]\.[0-9]-blue/version-$(APP_VERSION)-blue/g' docs/index.md
	@echo "$(OK) App version updated to $(APP_VERSION)"


# Tag the current version
tag-version:
	@echo "$(INFO) Tagging version..."
	@git tag -a v$(APP_VERSION) -m "Version $(APP_VERSION)"
	@git push origin v$(APP_VERSION)
	@echo "$(OK) Version $(APP_VERSION) tagged"
