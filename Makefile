TARGET_DIR=../htsat_kernel/drivers/net/ethernet/hisilicon/
CFLAGS=-O0 -g -I general_stub -I $(TARGET_DIR) 
COMM_FILES=ut.c comm.h

all: hns_enet.ut hnae.ut

hns_enet.ut: hns_enet.ut.c $(TARGET_DIR)/hns_enet.c $(COMM_FILES)
	$(CC) $(CFLAGS) $< -o $@

hnae.ut: hnae.ut.c $(TARGET_DIR)/hnae.c $(COMM_FILES)
	$(CC) $(CFLAGS) $< -o $@

test: all
	@./hns_enet.ut 2> ut.log
	@!(sed '/^[^0]/d' ut.log |addr2line -e hns_enet.ut |grep -v "ut/ut.c")
	@./hns_hnae.ut 2> ut.log
	@!(sed '/^[^0]/d' ut.log |addr2line -e hns_enet.ut |grep -v "ut/ut.c")

clean:
	@rm -f *.ut *.o *.log *.out

.PHONY: clean test all
