
APP_NAME=testprog

LIB_NAME=v2x_hsm_adaptation.a

HSM_LIB=../hsmstub/hsmstub.a

C_SOURCE=testprog.c

V2XSE_INC ?= ../adaptlib

$(APP_NAME): $(C_SOURCE) $(V2XSE_INC)/$(LIB_NAME)
	$(CC) -Wall $(C_SOURCE) $(V2XSE_INC)/$(LIB_NAME) $(HSM_LIB) -I$(V2XSE_INC)  -o $(APP_NAME)
