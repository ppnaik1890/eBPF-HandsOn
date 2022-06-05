LESSONS = $(wildcard tut*) $(wildcard common*) $(wildcard exercise*)

LESSONS_CLEAN = $(addsuffix _clean,$(LESSONS))

.PHONY: clean $(LESSONS) $(LESSONS_CLEAN)

all: $(LESSONS)
clean: $(LESSONS_CLEAN)

$(LESSONS):
	$(MAKE) -C $@

$(LESSONS_CLEAN):
	$(MAKE) -C $(subst _clean,,$@) clean