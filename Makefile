CC := gcc

TASK_1 := UDP/

.PHONY: all debug $(TASK_1) clean

all: $(TASK_1)

debug:
	cd $(TASK_1) && make debug

$(TASK_1):
	cd $(TASK_1) && make

clean:
	cd $(TASK_1) && make clean
