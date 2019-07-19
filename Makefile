
all: $(LIB_NAME)
APP_NAME=testprog

C_SOURCE=testprog.c

V2XSE_INC ?= ../adaptlib

all: $(APP_NAME)

.PHONY : clean
clean:
	rm -f testprog

$(APP_NAME): $(C_SOURCE) ../hsmstub/libhsmstub.a ../adaptlib/libv2xhsm.a
	$(CC) -Wall $(C_SOURCE) -L$(V2XSE_INC) -lv2xhsm -L../hsmstub -lhsmstub -I$(V2XSE_INC)  -o $(APP_NAME)
