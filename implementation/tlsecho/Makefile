SCENARIOS := scenarioa scenariob scenarioc scenariod scenarioe

.PHONY: all host tas clean $(SCENARIOS)

all:
	@for scenario in $(SCENARIOS); do $(MAKE) -C $$scenario all || exit $$?; done

host:
	@for scenario in $(SCENARIOS); do $(MAKE) -C $$scenario host || exit $$?; done

tas:
	@for scenario in scenariob scenarioc scenariod; do $(MAKE) -C $$scenario ta || exit $$?; done

$(SCENARIOS):
	$(MAKE) -C $@ all

clean:
	@for scenario in $(SCENARIOS); do $(MAKE) -C $$scenario clean || exit $$?; done
