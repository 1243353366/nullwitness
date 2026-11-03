# Java bridge between main (aired policy) and the experimental lab.
#
#   make            compile
#   make check      compile and run the self-test
#   make run        emit events from main's scenarios and refresh the summary
#
# Plain JDK 21, no dependencies, no network. JAVAC/JAVA can be overridden:
#   make check JAVAC=/opt/jdk/bin/javac JAVA=/opt/jdk/bin/java

JAVAC ?= javac
JAVA ?= java
OUT := out
SOURCES := $(wildcard src/lab/bridge/*.java)

all: $(OUT)/.built

$(OUT)/.built: $(SOURCES)
	@mkdir -p $(OUT)
	$(JAVAC) -Xlint:all -Werror -d $(OUT) $(SOURCES)
	@touch $(OUT)/.built

# Bridge paths are repository-relative, so commands run from the repo root.
check: all
	cd .. && $(JAVA) -cp bridge/$(OUT) lab.bridge.Bridge --selftest

run: all
	cd .. && $(JAVA) -cp bridge/$(OUT) lab.bridge.Bridge \
		--scenarios examples/scenarios.json \
		--emit lab/reports/scenario_events.jsonl \
		--summary lab/reports/last_run.json \
		--summary-out lab/reports/SUMMARY.md

clean:
	rm -rf $(OUT)

.PHONY: all check run clean
